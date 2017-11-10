// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

const SizeofCmsghdr = 0xc

// WSACMSGHDR
type cmsghdr struct {
	Len   uintptr
	Level int32
	Type  int32
}

const sizeofCmsghdr = 0xc

func (h *cmsghdr) set(l, lvl, typ int) {
	h.Len = uintptr(l)
	h.Level = int32(lvl)
	h.Type = int32(typ)
}

func controlHeaderLen() int {
	return controlMessageLen(0)
}

func controlMessageLen(dataLen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + dataLen
}

func controlMessageSpace(dataLen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + cmsgAlignOf(dataLen)
}

func cmsgAlignOf(salen int) int {
	salign := 0x8

	return (salen + salign - 1) & ^(salign - 1)
}
