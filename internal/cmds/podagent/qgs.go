package podagent

import (
	"encoding/binary"
	"fmt"
)

// QGS wire protocol (Intel DCAP tdx_attest): a 4-byte big-endian body length,
// then a little-endian message. This mirrors attestation-rs's vsock path,
// which skips the kernel's one-second ConfigFS polling loop.
const (
	qgsHeaderSize   = 16
	qgsGetQuoteReq  = 0
	qgsGetQuoteResp = 1
)

// qgsRequest frames a GetQuote request for one TDREPORT.
func qgsRequest(report []byte) ([]byte, error) {
	if len(report) != tdReportSize {
		return nil, fmt.Errorf("TDREPORT is %d bytes, want %d", len(report), tdReportSize)
	}
	inner := uint32(qgsHeaderSize + 4 + 4 + tdReportSize)
	msg := make([]byte, 0, 4+inner)
	msg = binary.BigEndian.AppendUint32(msg, inner)
	msg = binary.LittleEndian.AppendUint16(msg, 1) // major version
	msg = binary.LittleEndian.AppendUint16(msg, 0) // minor version
	msg = binary.LittleEndian.AppendUint32(msg, qgsGetQuoteReq)
	msg = binary.LittleEndian.AppendUint32(msg, inner)
	msg = binary.LittleEndian.AppendUint32(msg, 0) // error code
	msg = binary.LittleEndian.AppendUint32(msg, tdReportSize)
	msg = binary.LittleEndian.AppendUint32(msg, 0) // id list size
	return append(msg, report...), nil
}

// qgsQuote extracts the quote from a GetQuote response body (the bytes after
// the length prefix). Every length is host-supplied and checked.
func qgsQuote(body []byte) ([]byte, error) {
	if len(body) < qgsHeaderSize+8 {
		return nil, fmt.Errorf("QGS response is %d bytes, too short", len(body))
	}
	if major := binary.LittleEndian.Uint16(body[0:2]); major != 1 {
		return nil, fmt.Errorf("QGS response has unsupported major version %d", major)
	}
	if kind := binary.LittleEndian.Uint32(body[4:8]); kind != qgsGetQuoteResp {
		return nil, fmt.Errorf("QGS response has message type %d, want %d", kind, qgsGetQuoteResp)
	}
	if size := binary.LittleEndian.Uint32(body[8:12]); uint64(size) != uint64(len(body)) {
		return nil, fmt.Errorf("QGS response declares %d bytes, carries %d", size, len(body))
	}
	if code := binary.LittleEndian.Uint32(body[12:16]); code != 0 {
		return nil, fmt.Errorf("QGS returned error code %#x (check PCK provisioning on the host)", code)
	}
	idSize := uint64(binary.LittleEndian.Uint32(body[16:20]))
	quoteSize := uint64(binary.LittleEndian.Uint32(body[20:24]))
	start := uint64(qgsHeaderSize+8) + idSize
	end := start + quoteSize
	if quoteSize == 0 || end > uint64(len(body)) {
		return nil, fmt.Errorf("QGS response quote bounds [%d,%d) exceed %d bytes", start, end, len(body))
	}
	return append([]byte(nil), body[start:end]...), nil
}
