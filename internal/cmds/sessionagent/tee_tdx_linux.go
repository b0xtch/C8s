//go:build linux

package sessionagent

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

const (
	tdxGuestDevice = "/dev/tdx_guest"

	// TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req): 64 bytes of
	// REPORTDATA in, a 1024-byte TDREPORT out.
	tdxCmdGetReport0 = 0xC4405401

	vsockHoldOff = 30 * time.Second

	// The host's quoting service, as Intel's tdx_attest reaches it.
	vsockHostCID     = 2
	qgsVsockPort     = 4050
	qgsRoundTripSecs = 10
	qgsMaxResponse   = 64 * 1024
)

type tdxReportReq struct {
	ReportData [64]byte
	TDReport   [tdReportSize]byte
}

// tdxTEE talks to the TDX module through the guest kernel, and to the host's
// quoting service for quotes. No in-guest daemon stands between tenant code
// and a quote: only root can open the device or ConfigFS.
type tdxTEE struct {
	// vsockRetryAt (unix nanoseconds) holds the vsock path off after a
	// failure, so a guest with no route to QGS does not pay a failed connect on
	// every quote, and one transient failure does not cost the fast path for good.
	vsockRetryAt atomic.Int64
}

// OpenTEE returns the native TEE interface for platform ("tdx" or "snp").
func OpenTEE(platform string) (TEE, error) {
	switch platform {
	case "tdx":
		if _, err := os.Stat(tdxGuestDevice); err != nil {
			return nil, fmt.Errorf("this is not a TDX guest: %w", err)
		}
		return &tdxTEE{}, nil
	default:
		// SEV-SNP needs /dev/sev-guest report and extended-report support here.
		return nil, fmt.Errorf("platform %q has no in-guest attester yet", platform)
	}
}

func (t *tdxTEE) Family() teetypes.Family { return teetypes.FamilyTDX }

func (t *tdxTEE) Register() (runtimemeasure.Register, error) {
	return runtimemeasure.Open(teetypes.PlatformTDX)
}

func (t *tdxTEE) Measurements(context.Context) (*teetypes.VerificationResult, error) {
	report, err := tdReport([64]byte{})
	if err != nil {
		return nil, err
	}
	return claimsFromTDReport(report)
}

func (t *tdxTEE) Evidence(_ context.Context, reportData []byte) (teetypes.AttestationEvidence, error) {
	if len(reportData) == 0 || len(reportData) > 64 {
		return teetypes.AttestationEvidence{}, fmt.Errorf("report data must be 1..64 bytes, got %d", len(reportData))
	}
	var rd [64]byte
	copy(rd[:], reportData)
	quote, err := t.quote(rd)
	if err != nil {
		return teetypes.AttestationEvidence{}, err
	}
	return tdxEnvelope(quote)
}

// tdxEnvelope is a quote as a session's verifier takes it. The firmware's
// event log stays out: a verifier holds the quote's registers to published
// values and replays no log, and the log is many times the quote's size.
func tdxEnvelope(quote []byte) (teetypes.AttestationEvidence, error) {
	evidence, err := json.Marshal(struct {
		Quote string `json:"quote"`
	}{base64.StdEncoding.EncodeToString(quote)})
	if err != nil {
		return teetypes.AttestationEvidence{}, err
	}
	return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: evidence}, nil
}

// quote prefers the direct vsock path to the host's QGS (milliseconds) and
// falls back to ConfigFS-TSM, where the kernel polls once a second.
func (t *tdxTEE) quote(rd [64]byte) ([]byte, error) {
	var vsockErr error
	if now := time.Now().UnixNano(); now >= t.vsockRetryAt.Load() {
		quote, err := quoteVsock(rd)
		if err == nil {
			return quote, nil
		}
		vsockErr = err
		t.vsockRetryAt.Store(now + int64(vsockHoldOff))
	}
	resp, err := linuxtsm.GetReport(&report.Request{InBlob: rd[:]})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("ConfigFS-TSM quote: %w", err), vsockErr)
	}
	// The kernel reports a failed GetQuote as an empty read, not an error.
	if len(resp.OutBlob) == 0 {
		return nil, errors.Join(errors.New("ConfigFS-TSM returned an empty quote (GetQuote failed; check QGS and PCK provisioning on the host)"), vsockErr)
	}
	return resp.OutBlob, nil
}

func tdReport(rd [64]byte) ([]byte, error) {
	fd, err := unix.Open(tdxGuestDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tdxGuestDevice, err)
	}
	defer unix.Close(fd)
	req := tdxReportReq{ReportData: rd}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), tdxCmdGetReport0, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return nil, fmt.Errorf("TDX_CMD_GET_REPORT0: %w", errno)
	}
	return req.TDReport[:], nil
}

func quoteVsock(rd [64]byte) ([]byte, error) {
	report, err := tdReport(rd)
	if err != nil {
		return nil, err
	}
	request, err := qgsRequest(report)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	// os.File owns the descriptor from here; Close releases it on every path.
	sock := os.NewFile(uintptr(fd), "qgs-vsock")
	defer sock.Close()
	timeout := unix.Timeval{Sec: qgsRoundTripSecs}
	for _, opt := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &timeout); err != nil {
			return nil, fmt.Errorf("vsock timeout: %w", err)
		}
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: vsockHostCID, Port: qgsVsockPort}); err != nil {
		return nil, fmt.Errorf("vsock connect to host QGS port %d: %w", qgsVsockPort, err)
	}
	if _, err := sock.Write(request); err != nil {
		return nil, fmt.Errorf("vsock send: %w", err)
	}
	var size [4]byte
	if _, err := io.ReadFull(sock, size[:]); err != nil {
		return nil, fmt.Errorf("vsock read response size: %w", err)
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < qgsHeaderSize || n > qgsMaxResponse {
		return nil, fmt.Errorf("QGS response size %d out of range", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(sock, body); err != nil {
		return nil, fmt.Errorf("vsock read response: %w", err)
	}
	return qgsQuote(body)
}
