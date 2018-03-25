// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd solaris windows

package ipv6

import (
	"net"
	"unsafe"

	"golang.org/x/net/internal/socket"
)

func (so *sockOpt) setIPMreq(c *socket.Conn, ifi *net.Interface, grp net.IP) error {
	var mreq ipv6Mreq
	copy(mreq.Multiaddr[:], grp)
	if ifi != nil {
		mreq.setIfindex(ifi.Index)
	}
	b := (*[sizeofIPv6Mreq]byte)(unsafe.Pointer(&mreq))[:sizeofIPv6Mreq]
	return so.Set(c, b)
}

func netInterfaceToIP16(ifi *net.Interface) (net.IP, error) {
	if ifi == nil {
		return net.IPv6zero.To16(), nil
	}
	ifat, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, ifa := range ifat {
		switch ifa := ifa.(type) {
		case *net.IPAddr:
			if ip := ifa.IP.To16(); ip != nil {
				return ip, nil
			}
		case *net.IPNet:
			if ip := ifa.IP.To16(); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, errNoSuchInterface
}
