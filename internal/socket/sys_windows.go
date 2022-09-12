// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
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
)

type sockaddrInet struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type sockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

const (
	sizeofSockaddrInet  = 0x10
	sizeofSockaddrInet6 = 0x1c
)

func getsockopt(s uintptr, level, name int, b []byte) (int, error) {
	l := uint32(len(b))
	err := syscall.Getsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), (*int32)(unsafe.Pointer(&l)))
	return int(l), err
}

func setsockopt(s uintptr, level, name int, b []byte) error {
	return syscall.Setsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), int32(len(b)))
}

func recvmsg(s uintptr, h *msghdr, flags int) (int, error) {
	var bytesReceived uint32
	msg := (*WSAMsg)(h)
	msg.Flags = uint32(flags)
	controlLen := msg.Control.Len
	err := syscall.SetsockoptInt(syscall.Handle(s), syscall.SOL_SOCKET, SO_RCVTIMEO, 500)
	if err != nil {
		return 0, err
	}
	err = WSARecvMsg(syscall.Handle(s), msg, &bytesReceived, nil, nil)
	if err == WSAEMSGSIZE && (msg.Flags&MSG_CTRUNC) != 0 {
		// On windows, EMSGSIZE is raised in addition to MSG_CTRUNC, and
		// the original untruncated length of the control data is returned.
		// We reset the length back to the truncated portion which was received,
		// so the caller doesn't try to go out of bounds.
		// We also ignore the EMSGSIZE to emulate behavior of other platforms.
		msg.Control.Len = controlLen
		err = nil
	}
	if err == WSAETIMEDOUT {
		err = syscall.EAGAIN
	}
	return int(bytesReceived), err
}

func sendmsg(s uintptr, h *msghdr, flags int) (int, error) {
	var bytesSent uint32
	err := WSASendMsg(syscall.Handle(s), (*WSAMsg)(h), uint32(flags), &bytesSent, nil, nil)
	return int(bytesSent), err
}

func recvmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}

func sendmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}
