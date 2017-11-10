// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

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
