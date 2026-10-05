//go:build linux

package sessionagent

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// rulesetGeneration reads the kernel's count of the changes made to the
// packet filter of the network namespace this thread is in. The count moves
// with every change that takes effect, and with nothing else.
func rulesetGeneration() (uint32, error) {
	req := nl.NewNetlinkRequest(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETGEN, 0)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: unix.AF_UNSPEC, Version: nl.NFNETLINK_V0})
	answers, err := req.Execute(unix.NETLINK_NETFILTER, unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWGEN)
	if err != nil {
		return 0, fmt.Errorf("ask the kernel for the packet filter's generation: %w", err)
	}
	for _, answer := range answers {
		if len(answer) < nl.SizeofNfgenmsg {
			continue
		}
		attrs, err := nl.ParseRouteAttr(answer[nl.SizeofNfgenmsg:])
		if err != nil {
			return 0, fmt.Errorf("the kernel's answer about the packet filter's generation: %w", err)
		}
		for _, attr := range attrs {
			if attr.Attr.Type&nl.NLA_TYPE_MASK == unix.NFTA_GEN_ID && len(attr.Value) == 4 {
				return binary.BigEndian.Uint32(attr.Value), nil
			}
		}
	}
	return 0, errors.New("the kernel's answer names no generation of the packet filter")
}
