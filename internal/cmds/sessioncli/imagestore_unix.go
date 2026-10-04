//go:build unix

package sessioncli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
)

// imageStoreLimits bound one image in a store, as the guest's agent bounds a
// sandbox image it pulls.
var imageStoreLimits = imagestore.PullLimits{Layers: 256, BlobBytes: 8 << 30, TotalBytes: 16 << 30}

func imageStoreCmds() []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "image-store",
		Short: "The store of public images a host hands its guests",
		Long: `An image store is one file of public images, which a host hands the
guests it launches. A guest whose bind names one of these images reads it
from the store and asks no registry.

The store is not trusted by the guest. Every blob a guest takes from it is
checked against the digest that names it, starting from the digest in the
guest's own bind, exactly as a registry's answer is. A store that holds
something else costs the guest its image and nothing more.`,
	}
	cmd.AddCommand(imageStoreWriteCmd(), imageStoreCheckCmd())
	return []*cobra.Command{cmd}
}

func imageStoreWriteCmd() *cobra.Command {
	var out string
	var plainHTTP []string
	cmd := &cobra.Command{
		Use:   "write <image@sha256:digest>...",
		Short: "Pull images and write the store that holds them",
		Long: `Pull each image, for linux/amd64, and write its blobs into one file.

Put only public images here: the file is the host's, in the clear, and every
guest of the host is given it. An image named without a digest is refused.
What is written depends only on the images named.`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeImageStore(cmd.Context(), out, args, func(host string) bool { return slices.Contains(plainHTTP, host) }, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "the store file to write")
	cmd.Flags().StringSliceVar(&plainHTTP, "plain-http", nil, "registries (host:port) reached without TLS; an image is verified by its digest either way")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func imageStoreCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <store file>",
		Short: "Read a store whole and check each blob against the digest it is listed under",
		Long: `Read every blob the store lists and check that it is the blob its digest
names. A guest checks what it takes from a store anyway, and one that meets a
wrong blob at a bind ends, so that its session waits for another guest. A host
runs this over its store before it hands it out, and finds a damaged file
before a tenant does.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkImageStore(args[0], cmd.OutOrStdout())
		},
	}
}

// checkImageStore reads the store at path whole.
func checkImageStore(path string, stdout io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	store, err := imagestore.OpenStore(file, info.Size())
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	blobs, size, err := store.Check()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fmt.Fprintf(stdout, "%s  %d blobs, %d bytes, each the blob its digest names\n", path, blobs, size)
	return nil
}

// writeImageStore pulls refs and writes the store that holds them to out,
// whole or not at all.
func writeImageStore(ctx context.Context, out string, refs []string, plainHTTP func(string) bool, stdout io.Writer) error {
	dir := filepath.Dir(out)
	work, err := os.MkdirTemp(dir, ".image-store-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	var blobs []imagestore.StoreBlob
	for _, ref := range refs {
		// One content store for all of them: a blob two images share is
		// fetched once.
		puller := &imagestore.Puller{StoreDir: filepath.Join(work, "content"), Limits: imageStoreLimits, PlainHTTP: plainHTTP}
		img, err := puller.Pull(ctx, ref)
		if err != nil {
			return fmt.Errorf("%s: %w", ref, err)
		}
		of := img.Blobs(ctx)
		var size int64
		for _, blob := range of {
			size += blob.Size
		}
		fmt.Fprintf(stdout, "%s  %d blobs, %d bytes\n", ref, len(of), size)
		blobs = append(blobs, of...)
	}
	// In the work directory, which goes whatever happens here.
	tmp, err := os.OpenFile(filepath.Join(work, "store"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	buffered := bufio.NewWriterSize(io.MultiWriter(tmp, hash), 1<<20)
	err = imagestore.WriteStore(buffered, blobs)
	if err == nil {
		err = buffered.Flush()
	}
	if err == nil {
		// Read by a VMM that runs as another user, whatever the umask here.
		err = tmp.Chmod(0o644)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	info, err := os.Stat(tmp.Name())
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s  %d bytes  sha256:%s\n", out, info.Size(), hex.EncodeToString(hash.Sum(nil)))
	return nil
}
