// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

const sizeofCmsghdr = 0xc

func roundup(l int) int {
	var p uintptr
	kernelAlign := int(unsafe.Sizeof(p))
	return (l + kernelAlign - 1) &^ (kernelAlign - 1)
}

func controlHeaderLen() int {
	return roundup(sizeofCmsghdr)
}

func controlMessageLen(dataLen int) int {
	return roundup(sizeofCmsghdr) + dataLen
}

func controlMessageSpace(dataLen int) int {
	return roundup(sizeofCmsghdr) + roundup(dataLen)
}

// WSACMSGHDR
type cmsghdr struct {
	Len   uintptr
	Level int32
	Type  int32
}

func (h *cmsghdr) set(l, lvl, typ int) {
	h.Len = uintptr(l)
	h.Level = int32(lvl)
	h.Type = int32(typ)
}
