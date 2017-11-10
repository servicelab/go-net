// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"sync"
	"syscall"
	"unsafe"
)

const (
	socket_error = uintptr(^uint32(0))

	MSG_TRUNC  = 0x0100
	MSG_CTRUNC = 0x0200

	WSAEMSGSIZE syscall.Errno = 10040
)

type WSAMsg struct {
	Name        *syscall.RawSockaddrAny
	Namelen     int32
	Buffers     *syscall.WSABuf
	BufferCount uint32
	Control     syscall.WSABuf
	Flags       uint32
}

var WSAID_WSASENDMSG = syscall.GUID{
	0xa441e712,
	0x754f,
	0x43ca,
	[8]byte{0x84, 0xa7, 0x0d, 0xee, 0x44, 0xcf, 0x60, 0x6d},
}

var WSAID_WSARECVMSG = syscall.GUID{
	0xf689d7c8,
	0x6f1f,
	0x436b,
	[8]byte{0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22},
}

var sendRecvMsgFunc struct {
	once     sync.Once
	sendAddr uintptr
	recvAddr uintptr
	err      error
}

func loadWSASendRecvMsg() error {
	sendRecvMsgFunc.once.Do(func() {
		var s syscall.Handle
		s, sendRecvMsgFunc.err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if sendRecvMsgFunc.err != nil {
			return
		}
		defer syscall.CloseHandle(s)
		var n uint32
		sendRecvMsgFunc.err = syscall.WSAIoctl(s,
			syscall.SIO_GET_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(&WSAID_WSASENDMSG)),
			uint32(unsafe.Sizeof(WSAID_WSASENDMSG)),
			(*byte)(unsafe.Pointer(&sendRecvMsgFunc.sendAddr)),
			uint32(unsafe.Sizeof(sendRecvMsgFunc.sendAddr)),
			&n, nil, 0)
		if sendRecvMsgFunc.err != nil {
			return
		}
		sendRecvMsgFunc.err = syscall.WSAIoctl(s,
			syscall.SIO_GET_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(&WSAID_WSARECVMSG)),
			uint32(unsafe.Sizeof(WSAID_WSARECVMSG)),
			(*byte)(unsafe.Pointer(&sendRecvMsgFunc.recvAddr)),
			uint32(unsafe.Sizeof(sendRecvMsgFunc.recvAddr)),
			&n, nil, 0)
	})
	return sendRecvMsgFunc.err
}

func WSASendMsg(fd syscall.Handle, msg *WSAMsg, flags uint32, bytesSent *uint32, overlapped *syscall.Overlapped, croutine *byte) error {
	err := loadWSASendRecvMsg()
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall6(sendRecvMsgFunc.sendAddr, 6, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(flags), uintptr(unsafe.Pointer(bytesSent)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}

func WSARecvMsg(fd syscall.Handle, msg *WSAMsg, bytesReceived *uint32, overlapped *syscall.Overlapped, croutine *byte) error {
	err := loadWSASendRecvMsg()
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall6(sendRecvMsgFunc.recvAddr, 5, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(bytesReceived)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0)
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}
