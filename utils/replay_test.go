/**
 * replay_test.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReplayWriter(t *testing.T) {
	file := filepath.Join(os.TempDir(), "testfile")
	log.Println("TEMPFILE:", file)
	rw, err := NewReplayWriter(file)
	if err != nil {
		t.Errorf("failed to create RW: %s", err)
	}
	rw.WriteWindowSize(100, 100)
	<-time.NewTimer(time.Second).C
	rw.Write([]byte("Hello World"))
	<-time.NewTimer(time.Second).C
	rw.WriteStderr([]byte("Hello Stderr"))
	<-time.NewTimer(time.Second).C
	rw.WriteWindowSize(80, 50)
	rw.Close()
}
