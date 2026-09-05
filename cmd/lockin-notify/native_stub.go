//go:build !darwin || !cgo

package main

import (
	"context"
	"errors"
)

var errNativeUnavailable = errors.New("lockin-notify requires macOS and a cgo-enabled build")

func nativeInit(bool, bool) error { return errNativeUnavailable }
func nativeRun()                  {}
func nativeStop()                 {}
func nativeClear()                {}
func nativePermission(context.Context) (string, error) {
	return "unknown", errNativeUnavailable
}
func nativeReminder(context.Context, offer) error { return errNativeUnavailable }
func nativeResult(context.Context, string) error  { return errNativeUnavailable }
