//go:build !linux

package logx

import (
	"context"
	"io"
	"os"
)

func openConsoles() ([]io.Writer, []*ttySink) {
	return []io.Writer{os.Stderr}, []*ttySink{}
}

func (t *ttySink) measure() {}

func watchKernel(context.Context) {}
