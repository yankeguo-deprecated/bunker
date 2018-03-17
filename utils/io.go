/**
 * utils/io.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

type silentWriter struct {
	w io.Writer
}

func (sw *silentWriter) Write(p []byte) (n int, err error) {
	sw.w.Write(p)
	n = len(p)
	return
}

func (sw *silentWriter) Close() error {
	if c, ok := sw.w.(io.Closer); ok {
		c.Close()
		return nil
	}
	return nil
}

// NewSilentWriter returns a new io.WriteCloser which never returns error
func NewSilentWriter(w io.Writer) io.WriteCloser {
	return &silentWriter{w: w}
}

type lazyFilerWriter struct {
	filename string
	w        io.WriteCloser
	mtx      *sync.Mutex
}

func (lfw *lazyFilerWriter) ensureStream() (w io.WriteCloser, err error) {
	lfw.mtx.Lock()
	defer lfw.mtx.Unlock()
	if lfw.w != nil {
		w = lfw.w
		return
	}
	// ensure directory
	d := filepath.Dir(lfw.filename)
	if err = os.MkdirAll(d, os.FileMode(0750)); err != nil {
		return
	}
	var f *os.File
	if f, err = os.OpenFile(lfw.filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.FileMode(0640)); err != nil {
		return
	}
	lfw.w = f
	w = f
	return
}

func (lfw *lazyFilerWriter) Write(p []byte) (n int, err error) {
	var w io.WriteCloser
	if w, err = lfw.ensureStream(); err != nil {
		return
	}
	return w.Write(p)
}

func (lfw *lazyFilerWriter) Close() error {
	lfw.mtx.Lock()
	defer lfw.mtx.Unlock()
	if lfw.w != nil {
		return lfw.Close()
	}
	return nil
}

// NewLazyFileWriter lazy file writer, create file on first write
func NewLazyFileWriter(filename string) io.WriteCloser {
	return &lazyFilerWriter{filename: filename, mtx: &sync.Mutex{}}
}
