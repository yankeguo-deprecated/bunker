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

func (lfw *lazyFilerWriter) ensure() (wc io.WriteCloser, err error) {
	lfw.mtx.Lock()
	defer lfw.mtx.Unlock()
	// TODO:
	return
}

func (lfw *lazyFilerWriter) Write(p []byte) (n int, err error) {
	// TODO:
	return
}

func (lfw *lazyFilerWriter) Close() error {
	// TODO:
	return nil
}

// NewLazyFileWriter lazy file writer, create file on first write
func NewLazyFileWriter(filename string) io.WriteCloser {
	return &lazyFilerWriter{filename: filename, mtx: &sync.Mutex{}}
}
