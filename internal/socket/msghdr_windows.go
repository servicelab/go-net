// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"syscall"
	"unsafe"
)

type msghdr WSAMsg

func (h *msghdr) pack(vs []iovec, bs [][]byte, oob []byte, sa []byte) {
	for i := range vs {
		vs[i].set(bs[i])
	}
	h.setIov(vs)
	if len(oob) > 0 {
		h.Control.Buf = (*byte)(unsafe.Pointer(&oob[0]))
		h.Control.Len = uint32(len(oob))
	}
	if sa != nil {
		h.Name = (*syscall.RawSockaddrAny)(unsafe.Pointer(&sa[0]))
		h.Namelen = int32(len(sa))
	}
}

func (h *msghdr) name() []byte {
	if h.Name != nil && h.Namelen > 0 {
		return (*[sizeofSockaddrInet6]byte)(unsafe.Pointer(h.Name))[:h.Namelen]
	}
	return nil
}

func (h *msghdr) controllen() int {
	return int(h.Control.Len)
}

func (h *msghdr) flags() int {
	return int(h.Flags)
}

func (h *msghdr) setIov(vs []iovec) {
	l := len(vs)
	if l == 0 {
		return
	}
	h.Buffers = (*syscall.WSABuf)(unsafe.Pointer(&vs[0]))
	h.BufferCount = uint32(l)
}
