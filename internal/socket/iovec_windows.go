// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"syscall"
	"unsafe"
)

type iovec syscall.WSABuf

func (v *iovec) set(b []byte) {
	l := len(b)
	if l == 0 {
		return
	}
	v.Buf = (*byte)(unsafe.Pointer(&b[0]))
	v.Len = uint32(l)
}
