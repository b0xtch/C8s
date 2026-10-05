package sessionlauncher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/keyservice"
)

// opkeyLabel is the volume label the measured initrd looks for.
const opkeyLabel = "opkeydata"

// shutdownGrace is how long QEMU gets after SIGTERM. Guest state is ephemeral
// by construction, so there is nothing to flush.
const shutdownGrace = 10 * time.Second

// Run boots one guest and blocks until it exits or ctx ends. A guest that
// exits on its own is an error: whatever replaces it is attested afresh.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	pub, err := session.ReadBounded(filepath.Join(cfg.LaunchDir, session.PubkeyFile), 8192)
	if err != nil {
		return err
	}
	launch, err := session.ReadBounded(filepath.Join(cfg.LaunchDir, session.DocumentFile), session.MaxDocumentSize)
	if err != nil {
		return err
	}
	signature, err := session.ReadBounded(filepath.Join(cfg.LaunchDir, session.SignatureFile), 4096)
	if err != nil {
		return err
	}
	// The guest is the one that enforces this. Checking here only turns a
	// bundle that could never boot into an immediate, legible failure.
	platform, pinned, replica, described, err := describe(pub, launch, string(signature))
	if err != nil {
		return fmt.Errorf("launch bundle in %s: %w", cfg.LaunchDir, err)
	}
	if platform != cfg.Platform {
		return fmt.Errorf("launch document is for %s, launcher was asked for %s", platform, cfg.Platform)
	}
	if err := cfg.sim.open(&cfg); err != nil {
		return fmt.Errorf("simulated TEE: %w", err)
	}
	// Checked before any interface is touched.
	for _, name := range []string{firmwareFile(&cfg), diskFile} {
		if _, err := os.Stat(filepath.Join(cfg.ImageDir, name)); err != nil {
			return fmt.Errorf("guest image: %w", err)
		}
	}
	if cfg.ImageStore != "" {
		if info, err := os.Stat(cfg.ImageStore); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("--image-store %s is no file: %v", cfg.ImageStore, err)
		}
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return err
	}

	host := session.HostConfig{}
	// QEMU inherits these in order, starting at descriptor 3.
	var inherited []*os.File
	defer func() {
		for _, f := range inherited {
			f.Close()
		}
	}()
	inherit := func(f *os.File) int {
		inherited = append(inherited, f)
		return 2 + len(inherited)
	}
	switch cfg.Network {
	case NetworkUser:
		// A session guest has no DHCP client: the launcher says outright
		// what QEMU's user-mode stack would have answered.
		host.Network = userNetwork()
	case NetworkTap:
		network, mac, tap, vhost, err := setupTap(&cfg)
		if err != nil {
			return fmt.Errorf("tap network: %w", err)
		}
		host.Network = network
		cfg.tap = &tapDevice{mac: mac, fd: inherit(tap)}
		if vhost != nil {
			cfg.tap.vhostFD = inherit(vhost)
		}
	case NetworkFD:
		tap, err := inheritedFile(cfg.TapFD, "tap")
		if err != nil {
			return fmt.Errorf("--tap-fd: %w", err)
		}
		guest := cfg.Guest
		host.Network = &guest
		cfg.tap = &tapDevice{mac: cfg.MAC, fd: inherit(tap)}
		if cfg.VhostFD != -1 {
			vhost, err := inheritedFile(cfg.VhostFD, "vhost-net")
			if err != nil {
				return fmt.Errorf("--vhost-fd: %w", err)
			}
			cfg.tap.vhostFD = inherit(vhost)
		}
	}
	if cfg.VsockAuto {
		device, cid, err := reserveVsock()
		if err != nil {
			return fmt.Errorf("vsock: %w", err)
		}
		cfg.vsock = &vsockDevice{cid: cid, fd: inherit(device)}
	}
	// A guest with a vsock device reaches its key service through its
	// launcher. One without dials the key service's address itself.
	var carrier *relay
	if cid := cfg.guestCID(); pinned != nil && cid != 0 {
		if carrier, host.KeyServicePort, err = keyServiceRelay(pinned, cid, log); err != nil {
			return fmt.Errorf("key service relay: %w", err)
		}
		defer carrier.ln.Close()
		described = append(described, "key_service_port", host.KeyServicePort)
	}
	// A guest with no network device is reached on ports of its socket to
	// the host, which the launcher publishes on the host.
	var carriers []*relay
	if cfg.Network == NetworkNone {
		for _, forward := range cfg.Forwards {
			publisher, err := publishRelay(forward, cfg.guestCID(), log)
			if err != nil {
				return fmt.Errorf("--port %d: %w", forward.Host, err)
			}
			defer publisher.ln.Close()
			carriers = append(carriers, publisher)
		}
	}
	// A key service replica judges guests by the vendor's documents, which
	// it takes from the vendor itself. One with a vsock device is carried
	// there by its launcher, and needs no network device for it.
	if cid := cfg.guestCID(); replica && cid != 0 {
		roads, ports, err := vendorRoads(&cfg, cid, log)
		for _, road := range roads {
			defer road.ln.Close()
		}
		if err != nil {
			return fmt.Errorf("vendor relay: %w", err)
		}
		carriers = append(carriers, roads...)
		host.VendorPorts = ports
		described = append(described, "vendor_services", len(ports))
	}
	// A TD with a vsock device asks its launcher for Intel's documents for
	// its platform. The launcher looks for them now, ahead of the ask.
	if cid := cfg.guestCID(); cfg.Collateral && cfg.Platform == "tdx" && cid != 0 {
		keeper, port, err := collateralStock(&cfg, cid, log)
		if err != nil {
			return fmt.Errorf("collateral: %w", err)
		}
		host.CollateralPort = port
		keeping, stop := context.WithCancel(ctx)
		defer stop()
		go keeper.run(keeping)
	}
	// Every file of the guest reaches QEMU open, so it is given no path into
	// the image directory or the work directory and needs no right to enter
	// either.
	cfg.disks = &diskFiles{}
	var image [2]*os.File
	for i, file := range []struct {
		name string
		fd   *int
	}{{firmwareFile(&cfg), &cfg.disks.firmware}, {diskFile, &cfg.disks.root}} {
		f, err := os.Open(filepath.Join(cfg.ImageDir, file.name))
		if err != nil {
			return fmt.Errorf("guest image: %w", err)
		}
		*file.fd, image[i] = inherit(f), f
	}
	hostJSON, err := json.Marshal(host)
	if err != nil {
		return err
	}
	files := []ISOFile{
		{Name: session.PubkeyFile, Data: pub},
		{Name: session.DocumentFile, Data: launch},
		{Name: session.SignatureFile, Data: signature},
		{Name: session.HostConfigFile, Data: hostJSON},
	}
	// What stands for the guest's hardware where its TEE is simulated: the
	// registers of the image these two open files are.
	hardware, err := cfg.sim.declare(&cfg, image[0], image[1])
	if err != nil {
		return fmt.Errorf("simulated TEE: %w", err)
	}
	iso, err := BuildISO(opkeyLabel, append(files, hardware...))
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(cfg.WorkDir, opkeyISO), iso, 0o600); err != nil {
		return fmt.Errorf("write launch disk: %w", err)
	}
	opkey, err := os.Open(filepath.Join(cfg.WorkDir, opkeyISO))
	if err != nil {
		return fmt.Errorf("open launch disk: %w", err)
	}
	cfg.disks.opkey = inherit(opkey)
	if cfg.ImageStore != "" {
		// For reading only: a guest cannot change what the next one reads.
		images, err := os.Open(cfg.ImageStore)
		if err != nil {
			return fmt.Errorf("open image store: %w", err)
		}
		cfg.disks.images = inherit(images)
	}
	if cfg.ScratchMiB > 0 {
		scratch, err := createSparse(filepath.Join(cfg.WorkDir, scratchFile), int64(cfg.ScratchMiB)<<20)
		if err != nil {
			return fmt.Errorf("create scratch disk: %w", err)
		}
		cfg.disks.scratch = inherit(scratch)
	}
	args, err := cfg.QEMUArgs(pub)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, cfg.QEMU, args...)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = inherited
	if cfg.Confine != nil {
		if cmd.SysProcAttr, err = cfg.Confine.sysProcAttr(cfg.Network); err != nil {
			return fmt.Errorf("--confine: %w", err)
		}
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = shutdownGrace
	if cfg.sim.on() {
		log.Warn("this guest runs in no TEE: its launcher declared its registers and handed it its platform's quoting enclave", cfg.sim.note()...)
	}
	log.Info("starting guest", append([]any{"platform", cfg.Platform,
		"launch_digest", session.DocumentDigest(launch), "vcpus", cfg.VCPUs, "memory_mib", cfg.MemoryMiB, "network", cfg.Network},
		described...)...)
	avoid, err := cfg.avoidCPUs()
	if err != nil {
		return fmt.Errorf("--avoid-first-cpu: %w", err)
	}
	started := time.Now()
	var off []int
	if off, err = startAway(cmd, avoid); err == nil {
		if len(off) > 0 {
			log.Info("the VMM is kept off the first CPU of each package", "cpus", off)
		}
		if carrier != nil {
			carriers = append(carriers, carrier)
		}
		carrying, stop := context.WithCancel(ctx)
		var relays sync.WaitGroup
		for _, each := range carriers {
			relays.Go(func() { each.run(carrying) })
		}
		err = cmd.Wait()
		// Each relay says what it carried once its connections have ended.
		stop()
		relays.Wait()
	}
	// The scratch disk held only ciphertext under a key that died with the
	// guest; removing it just returns the space.
	_ = os.Remove(filepath.Join(cfg.WorkDir, scratchFile))
	_ = os.Remove(filepath.Join(cfg.WorkDir, opkeyISO))
	uptime := time.Since(started).Round(time.Millisecond).String()
	if ctx.Err() != nil {
		log.Info("guest stopped", "uptime", uptime)
		return nil
	}
	if err != nil {
		return fmt.Errorf("guest exited after %s: %w", uptime, err)
	}
	return fmt.Errorf("guest exited on its own after %s", uptime)
}

// describe reads a bundle's launch document: a session pool's, or a key
// service's, which boots from a bundle of the same layout. It returns the
// platform the document is for, the key service a pool's document pins,
// whether the document is a key service replica's, and what to log of it.
func describe(pub, launch []byte, signature string) (platform string, pinned *session.KeyService, replica bool, described []any, err error) {
	doc, err := session.VerifySigned(pub, launch, signature)
	if err == nil {
		return doc.Image.Platform, doc.KeyService, false, []any{"pool", doc.Pool, "class", doc.Class}, nil
	}
	if service, serviceErr := keyservice.VerifySigned(pub, launch, signature); serviceErr == nil {
		return service.Image.Platform, nil, true, []any{"key_service_pools", len(service.Pools)}, nil
	}
	return "", nil, false, nil, err
}

// avoidCPUs lists the CPUs this guest's VMM is kept off: on TDX, the ones the
// host writes its caches back on when any guest's key is freed.
func (c *Config) avoidCPUs() ([]int, error) {
	if !c.AvoidFirstCPU || c.Platform != "tdx" {
		return nil, nil
	}
	return writeBackCPUs()
}

// guestCID is the guest's vsock context id, or zero for a guest without a
// vsock device.
func (c *Config) guestCID() uint32 {
	if c.vsock != nil {
		return c.vsock.cid
	}
	return c.VsockCID
}

// firmwareFile is what the platform boots besides the image's disk: the TDX
// firmware, or the IGVM file for this many vCPUs on SEV-SNP.
func firmwareFile(cfg *Config) string {
	if cfg.Platform == "tdx" {
		return tdxFirmwareFile
	}
	return fmt.Sprintf("guest-smp%d.igvm", cfg.VCPUs)
}

// createSparse makes a fresh file of size bytes that occupies no blocks until
// the guest writes to it, and returns it open the way QEMU opens a disk it
// does not cache: for reading and writing, with direct I/O.
func createSparse(path string, size int64) (*os.File, error) {
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|directIO, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// inheritedFile wraps a descriptor this process was started with. QEMU gets
// it under the number its arguments name and under no other.
func inheritedFile(fd int, name string) (*os.File, error) {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return nil, fmt.Errorf("descriptor %d is not open", fd)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), name), nil
}

// pickCID tries random context ids until claim takes one. Ids below 2^16 are
// left to operators who assign them by hand.
func pickCID(claim func(cid uint64) error) (uint32, error) {
	const lowest, attempts = 1 << 16, 32
	for range attempts {
		cid := lowest + rand.Uint32N(1<<31-lowest)
		switch err := claim(uint64(cid)); {
		case err == nil:
			return cid, nil
		case !errors.Is(err, syscall.EADDRINUSE):
			return 0, fmt.Errorf("reserve context id %d: %w", cid, err)
		}
	}
	return 0, fmt.Errorf("no free context id in %d attempts", attempts)
}
