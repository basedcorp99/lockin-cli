//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework AppKit -framework UserNotifications -framework Foundation -framework CoreServices
#include <stdlib.h>
#include "native.h"
*/
import "C"

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

type nativeReply struct {
	value string
	err   string
}

var nativeRequests = struct {
	sync.Mutex
	next    uint64
	pending map[uint64]chan nativeReply
}{pending: make(map[uint64]chan nativeReply)}

func init() { runtime.LockOSThread() }

func nativeInit(authorize, statusOnly bool) error {
	var a, s C.int
	if authorize {
		a = 1
	}
	if statusOnly {
		s = 1
	}
	if C.lockin_native_init(a, s) != 0 {
		return errors.New("native notifications require the installed Lockin Alerts.app bundle")
	}
	return nil
}

func nativeRun()   { C.lockin_native_run() }
func nativeStop()  { C.lockin_native_stop() }
func nativeClear() { C.lockin_native_clear() }

func nativeCall(ctx context.Context, invoke func(C.ulonglong)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	nativeRequests.Lock()
	nativeRequests.next++
	token := nativeRequests.next
	reply := make(chan nativeReply, 1)
	nativeRequests.pending[token] = reply
	nativeRequests.Unlock()
	defer func() {
		nativeRequests.Lock()
		delete(nativeRequests.pending, token)
		nativeRequests.Unlock()
	}()
	invoke(C.ulonglong(token))
	select {
	case result := <-reply:
		if result.err != "" {
			return "", errors.New(result.err)
		}
		return result.value, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func nativePermission(ctx context.Context) (string, error) {
	return nativeCall(ctx, func(token C.ulonglong) { C.lockin_native_settings(token) })
}

func nativeReminder(ctx context.Context, a offer) error {
	_, err := nativeCall(ctx, func(token C.ulonglong) {
		id, message, label := C.CString(a.ID), C.CString(a.Message), C.CString(a.Label)
		defer C.free(unsafe.Pointer(id))
		defer C.free(unsafe.Pointer(message))
		defer C.free(unsafe.Pointer(label))
		C.lockin_native_reminder(token, id, message, label)
	})
	return err
}

func nativeResult(ctx context.Context, text string) error {
	_, err := nativeCall(ctx, func(token C.ulonglong) {
		message := C.CString(text)
		defer C.free(unsafe.Pointer(message))
		C.lockin_native_result(token, message)
	})
	return err
}

//export goNativeComplete
func goNativeComplete(token C.ulonglong, value, errorText *C.char) {
	// Copy native callback memory before returning. Never perform IO on a native callback.
	result := nativeReply{value: C.GoString(value), err: C.GoString(errorText)}
	nativeRequests.Lock()
	reply := nativeRequests.pending[uint64(token)]
	nativeRequests.Unlock()
	if reply != nil {
		select {
		case reply <- result:
		default:
		}
	}
}

//export goNativeAction
func goNativeAction(id *C.char) {
	handoffAction(C.GoString(id))
}
