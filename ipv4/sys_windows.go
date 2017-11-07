// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"net"
	"unsafe"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"
)

const (
	// See ws2tcpip.h.
	sysIP_OPTIONS                = 0x1
	sysIP_HDRINCL                = 0x2
	sysIP_TOS                    = 0x3
	sysIP_TTL                    = 0x4
	sysIP_MULTICAST_IF           = 0x9
	sysIP_MULTICAST_TTL          = 0xa
	sysIP_MULTICAST_LOOP         = 0xb
	sysIP_ADD_MEMBERSHIP         = 0xc
	sysIP_DROP_MEMBERSHIP        = 0xd
	sysIP_DONTFRAGMENT           = 0xe
	sysIP_ADD_SOURCE_MEMBERSHIP  = 0xf
	sysIP_DROP_SOURCE_MEMBERSHIP = 0x10
	sysIP_PKTINFO                = 0x13

	sizeofInetPktinfo  = 0x8
	sizeofIPMreq       = 0x8
	sizeofIPMreqSource = 0xc
)

type inetPktinfo struct {
	Addr    [4]byte
	Ifindex int32
}

type ipMreq struct {
	Multiaddr [4]byte
	Interface [4]byte
}

type ipMreqSource struct {
	Multiaddr  [4]byte
	Sourceaddr [4]byte
	Interface  [4]byte
}

// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms738586(v=vs.85).aspx
var (
	ctlOpts = [ctlMax]ctlOpt{
		ctlPacketInfo: {sysIP_PKTINFO, sizeofInetPktinfo, marshalPacketInfo, parsePacketInfo},
	}

	sockOpts = map[int]*sockOpt{
		ssoTOS:                {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_TOS, Len: 4}},
		ssoTTL:                {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_TTL, Len: 4}},
		ssoMulticastTTL:       {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_MULTICAST_TTL, Len: 4}},
		ssoMulticastInterface: {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_MULTICAST_IF, Len: 4}},
		ssoMulticastLoopback:  {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_MULTICAST_LOOP, Len: 4}},
		ssoHeaderPrepend:      {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_HDRINCL, Len: 4}},
		ssoJoinGroup:          {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_ADD_MEMBERSHIP, Len: sizeofIPMreq}, typ: ssoTypeIPMreq},
		ssoLeaveGroup:         {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_DROP_MEMBERSHIP, Len: sizeofIPMreq}, typ: ssoTypeIPMreq},
		ssoPacketInfo:         {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_PKTINFO, Len: 4}},
	}
)

func (pi *inetPktinfo) setIfindex(i int) {
	pi.Ifindex = int32(i)
}

func marshalPacketInfo(b []byte, cm *ControlMessage) []byte {
	m := socket.ControlMessage(b)
	m.MarshalHeader(iana.ProtocolIP, sysIP_PKTINFO, sizeofInetPktinfo)
	if cm != nil {
		pi := (*inetPktinfo)(unsafe.Pointer(&m.Data(sizeofInetPktinfo)[0]))
		if ip := cm.Src.To4(); ip != nil {
			copy(pi.Addr[:], ip)
		}
		if cm.IfIndex > 0 {
			pi.setIfindex(cm.IfIndex)
		}
	}
	return m.Next(sizeofInetPktinfo)
}

func parsePacketInfo(cm *ControlMessage, b []byte) {
	pi := (*inetPktinfo)(unsafe.Pointer(&b[0]))
	cm.IfIndex = int(pi.Ifindex)
	if len(cm.Dst) < net.IPv4len {
		cm.Dst = make(net.IP, net.IPv4len)
	}
	copy(cm.Dst, pi.Addr[:])
}
