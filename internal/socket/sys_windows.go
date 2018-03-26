// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func probeProtocolStack() int {
	var p uintptr
	return int(unsafe.Sizeof(p))
}

const (
	sysAF_UNSPEC = windows.AF_UNSPEC
	sysAF_INET   = windows.AF_INET
	sysAF_INET6  = windows.AF_INET6

	sysSOCK_RAW = windows.SOCK_RAW

	sizeofSockaddrInet4 = 0x10
	sizeofSockaddrInet6 = 0x1c
	sizeofSockaddrAny   = 0x6c
)

func getsockopt(s uintptr, level, name int, b []byte) (int, error) {
	l := uint32(len(b))
	err := syscall.Getsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), (*int32)(unsafe.Pointer(&l)))
	return int(l), err
}

func setsockopt(s uintptr, level, name int, b []byte) error {
	return syscall.Setsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), int32(len(b)))
}

func recvmsg(s uintptr, buffers [][]byte, oob []byte, flags int, network string) (n, oobn int, recvflags int, from net.Addr, err error) {
	var bytesReceived uint32
	var msg windows.WSAMsg
	if len(buffers) > 0 {
		vs := make([]iovec, len(buffers))
		for i := range vs {
			vs[i].set(buffers[i])
		}
		msg.Buffers = (*windows.WSABuf)(unsafe.Pointer(&vs[0]))
		msg.BufferCount = uint32(len(buffers))
	}
	if len(oob) > 0 {
		msg.Control.Buf = (*byte)(unsafe.Pointer(&oob[0]))
		msg.Control.Len = uint32(len(oob))
	}

	var rsa windows.RawSockaddrAny
	msg.Name = (*syscall.RawSockaddrAny)(unsafe.Pointer(&rsa))
	msg.Namelen = int32(unsafe.Sizeof(rsa))
	msg.Flags = uint32(flags)

	err = syscall.SetsockoptInt(syscall.Handle(s), syscall.SOL_SOCKET, windows.SO_RCVTIMEO, 500)
	if err != nil {
		return
	}

	err = windows.WSARecvMsg(windows.Handle(s), &msg, &bytesReceived, nil, nil)
	if err == WSAEMSGSIZE && (msg.Flags&windows.MSG_CTRUNC) != 0 {
		// On windows, EMSGSIZE is raised in addition to MSG_CTRUNC, and
		// the original untruncated length of the control data is returned.
		// We reset the length back to the truncated portion which was received,
		// so the caller doesn't try to go out of bounds.
		// We also ignore the EMSGSIZE to emulate behavior of other platforms.
		msg.Control.Len = uint32(len(oob))
		err = nil
	}
	if err == windows.WSAETIMEDOUT {
		err = syscall.EAGAIN
	}

	n = int(bytesReceived)
	oobn = int(msg.Control.Len)
	recvflags = int(msg.Flags)
	if err == nil && rsa.Addr.Family != windows.AF_UNSPEC {
		faddr, err := rsa.Sockaddr()
		if err == nil {
			from = sockaddrToAddr(faddr, network)
		}
	}

	return
}

func sendmsg(s uintptr, buffers [][]byte, oob []byte, to net.Addr, flags int) (int, error) {
	var msg windows.WSAMsg
	if len(buffers) > 0 {
		vs := make([]iovec, len(buffers))
		for i := range vs {
			vs[i].set(buffers[i])
		}
		msg.Buffers = (*windows.WSABuf)(unsafe.Pointer(&vs[0]))
		msg.BufferCount = uint32(len(buffers))
	}
	if len(oob) > 0 {
		msg.Control.Buf = (*byte)(unsafe.Pointer(&oob[0]))
		msg.Control.Len = uint32(len(oob))
	}

	if to != nil {
		var a [sizeofSockaddrInet6]byte
		n := marshalInetAddr(to, a[:])
		sa := a[:n]

		msg.Name = (*syscall.RawSockaddrAny)(unsafe.Pointer(&sa[0]))
		msg.Namelen = int32(n)
	}

	var bytesSent uint32
	err := windows.WSASendMsg(windows.Handle(s), &msg, uint32(flags), &bytesSent, nil, nil)
	return int(bytesSent), err
}

func recvmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}

func sendmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}

// addrToSockaddr converts a net.Addr to a windows.Sockaddr.
func addrToSockaddr(a net.Addr) windows.Sockaddr {
	var (
		ip   net.IP
		port int
		zone string
	)
	switch a := a.(type) {
	case *net.TCPAddr:
		ip = a.IP
		port = a.Port
		zone = a.Zone
	case *net.UDPAddr:
		ip = a.IP
		port = a.Port
		zone = a.Zone
	case *net.IPAddr:
		ip = a.IP
		zone = a.Zone
	default:
		return nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		sa := windows.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip4)
		return &sa
	}

	if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil {
		sa := windows.SockaddrInet6{Port: port}
		copy(sa.Addr[:], ip6)
		if zone != "" {
			sa.ZoneId = uint32(zoneCache.index(zone))
		}
		return &sa
	}

	return nil
}

// sockaddrToAddr converts a windows.Sockaddr to a net.Addr.
func sockaddrToAddr(sa windows.Sockaddr, network string) net.Addr {
	var (
		ip   net.IP
		port int
		zone string
	)
	switch sa := sa.(type) {
	case *windows.SockaddrInet4:
		ip = make(net.IP, net.IPv4len)
		copy(ip, sa.Addr[:])
		port = sa.Port
	case *windows.SockaddrInet6:
		ip = make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])
		port = sa.Port
		if sa.ZoneId > 0 {
			zone = zoneCache.name(int(sa.ZoneId))
		}
	default:
		return nil
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: ip, Port: port, Zone: zone}
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: ip, Port: port, Zone: zone}
	default:
		return &net.IPAddr{IP: ip, Zone: zone}
	}
}
