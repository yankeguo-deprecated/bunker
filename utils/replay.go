/**
 * replay.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	errReplayFileFailedToCreate = errors.New("replay file fialed to create")
	errReplayUnknownFrame       = errors.New("replay file unknown frame")
)

const dirPerm = os.FileMode(0750)
const filePerm = os.FileMode(0640)

const replayFrameStdout = byte(1)
const replayFrameStderr = byte(2)
const replayFrameWindowSize = byte(3)

/**
 * Replay Format (Uncompressed)
 *
 * 1. 4 Bytes, milliseconds from beginning, uint32
 * 2. 1 Byte, Frame Type, ( 1 = stdout, 2 = stderr, 3 = window size)
 * 3. X Bytes, Payload
 *   3.1 case stdout / stderr
 *     3.1.1 4 Bytes, lengths of bytes, uint32
 *     3.1.2 X Bytes, bytes
 *   3.2 case window size
 *     3.2.1 4 Bytes, width, uint32
 *     3.2.2 4 Bytes, height, uint32
 */

// ReplayWriter replay writer
type ReplayWriter interface {
	io.WriteCloser
	Activate()
	Stderr() io.Writer
	WriteStderr(p []byte) (n int, err error)
	WriteWindowSize(w, h uint) error
}

type replayStderrWriter struct {
	rw *replayWriter
}

func (rew *replayStderrWriter) Write(p []byte) (n int, err error) {
	return rew.rw.WriteStderr(p)
}

type replayWriter struct {
	t0       time.Time
	w        io.WriteCloser
	active   bool
	filename string
	failed   bool
	mutex    *sync.Mutex
}

func (rw *replayWriter) Activate() {
	if len(rw.filename) > 0 {
		log.Println("RPW ACTIVATED:", rw.filename)
		rw.active = true
	}
}

func (rw *replayWriter) ts() uint32 {
	ns := time.Now().Sub(rw.t0).Nanoseconds() / int64(time.Millisecond)
	if ns < 0 {
		return 0
	}
	return uint32(ns)
}

func (rw *replayWriter) Stderr() io.Writer {
	return &replayStderrWriter{rw: rw}
}

// ignore all errors
func (rw *replayWriter) WriteStderr(p []byte) (n int, err error) {
	rw.write(replayFrameStderr, 0, 0, p)
	n = len(p)
	return
}

// ignore all errors
func (rw *replayWriter) Write(p []byte) (n int, err error) {
	err = rw.write(replayFrameStdout, 0, 0, p)
	n = len(p)
	return
}

func (rw *replayWriter) Close() error {
	// lock / unlock
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if rw.w != nil {
		return rw.w.Close()
	}
	return nil
}

func (rw *replayWriter) WriteWindowSize(w, h uint) error {
	return rw.write(replayFrameWindowSize, uint32(w), uint32(h), nil)
}

func (rw *replayWriter) write(t byte, w, h uint32, p []byte) (err error) {
	// check active
	if !rw.active {
		return
	}

	// lock / unlock
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// ensure output io.Writer
	if rw.w == nil {
		// already failed
		if rw.failed {
			err = errReplayFileFailedToCreate
			return
		}
		// ensure dir
		if err = os.MkdirAll(filepath.Dir(rw.filename), dirPerm); err != nil {
			rw.failed = true
			err = errReplayFileFailedToCreate
			return
		}
		// create file and gzip stream
		var f *os.File
		if f, err = os.OpenFile(rw.filename, os.O_CREATE|os.O_RDWR, filePerm); err != nil {
			rw.failed = true
			err = errReplayFileFailedToCreate
			return
		}
		rw.w = gzip.NewWriter(f)
		rw.t0 = time.Now()
	}

	// write to rw.w
	var out []byte
	switch t {
	case replayFrameWindowSize:
		out = make([]byte, 13, 13)
		binary.BigEndian.PutUint32(out, rw.ts())
		out[4] = t
		binary.BigEndian.PutUint32(out[5:], w)
		binary.BigEndian.PutUint32(out[9:], h)
	case replayFrameStderr, replayFrameStdout:
		out = make([]byte, 9+len(p), 9+len(p))
		binary.BigEndian.PutUint32(out, rw.ts())
		out[4] = t
		binary.BigEndian.PutUint32(out[5:], uint32(len(p)))
		copy(out[9:], p)
	default:
		err = errors.New("unknown frame type")
		return
	}
	_, err = rw.w.Write(out)
	return
}

// NewReplayWriter create a new replay writer
func NewReplayWriter(filename string) ReplayWriter {
	return &replayWriter{
		filename: filename,
		mutex:    &sync.Mutex{},
	}
}
