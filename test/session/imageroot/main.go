// Command imageroot unpacks one image of an image store into a directory, as
// a session guest's agent unpacks the image its bind names: the tree a
// sandbox of that image runs on.
//
//	imageroot -store images.store -image name@sha256:<digest> -out <dir>
//
// The Firecracker baseline of test/session/burst.sh gives its guest that
// tree, so that a session's first command and the baseline's run from the
// same files. It prints the image's environment, one KEY=VALUE a line.
//
// The tree's files are owned by the ids a sandbox maps to its own, as the
// agent leaves them, so the command runs as root.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/imagestore"
)

// The bounds a guest's agent holds a sandbox image to.
var (
	pullLimits   = imagestore.PullLimits{Layers: 256, BlobBytes: 8 << 30, TotalBytes: 16 << 30}
	unpackLimits = imagestore.UnpackLimits{Entries: 4 << 20, Bytes: 32 << 30}
)

func main() {
	store := flag.String("store", "", "the image store ('c8s session image-store write')")
	image := flag.String("image", "", "the image to unpack, as name@sha256:<digest>")
	out := flag.String("out", "", "the directory to make, which must not exist")
	flag.Parse()
	if err := run(*store, *image, *out); err != nil {
		fmt.Fprintln(os.Stderr, "imageroot:", err)
		os.Exit(1)
	}
}

func run(storePath, ref, out string) (err error) {
	if storePath == "" || ref == "" || out == "" {
		return errors.New("-store, -image and -out are required")
	}
	file, err := os.Open(storePath)
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
		return fmt.Errorf("%s: %w", storePath, err)
	}
	work, err := os.MkdirTemp(filepath.Dir(out), ".imageroot-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// From the store alone, each blob held to its digest, as in a guest.
	puller := &imagestore.Puller{StoreDir: filepath.Join(work, "content"), Limits: pullLimits, Images: store, ImagesOnly: true}
	img, err := puller.Pull(ctx, ref)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	unpacker, err := imagestore.NewUnpacker(out, unpackLimits)
	if err != nil {
		return err
	}
	// A tree that is not whole is none.
	defer func() {
		if err != nil {
			_ = os.RemoveAll(out)
		}
	}()
	if err := img.Unpack(ctx, unpacker); err != nil {
		return err
	}
	if _, err := unpacker.Finish(); err != nil {
		return err
	}
	for _, variable := range img.Config.Config.Env {
		fmt.Println(variable)
	}
	return nil
}
