/**
 * sandbox/sandbox.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"landzero.net/x/os/minit"
)

// Window pty window size
type Window struct {
	Width  uint
	Height uint
}

// Pty pty information
type Pty struct {
	Term   string
	Window Window
}

// ExecAttachOptions opts for exec attach
type ExecAttachOptions struct {
	Env        []string
	Command    []string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	IsPty      bool
	Term       string
	WindowChan chan Window
}

// Sandbox interface
type Sandbox interface {
	GetContainerName() string
	Start() error
	GenerateSSHKey() error
	GetSSHPublicKey() (string, error)
	ExecScript(sc string) (string, string, error)
	ExecAttach(opts ExecAttachOptions) error
}

type sandbox struct {
	client *client.Client
	sock   string
	name   string
}

func (s *sandbox) GetContainerName() string {
	return s.name
}

func (s *sandbox) Start() error {
	return s.client.ContainerStart(context.Background(), s.name, dtypes.ContainerStartOptions{})
}

func (s *sandbox) GenerateSSHKey() (err error) {
	_, _, err = s.ExecScript(scriptGenerateSSHKey)
	return
}

func (s *sandbox) GetSSHPublicKey() (pkey string, err error) {
	pkey, _, err = s.ExecScript(`cat /root/.ssh/id_rsa.pub`)
	pkey = strings.TrimSpace(pkey)
	return
}

func (s *sandbox) ExecScript(sc string) (stdout string, stderr string, err error) {
	// dial
	var c minit.Conn
	cmd := minit.Command{
		Cmd: []string{"/bin/bash"},
	}
	if c, err = minit.Dial("unix", s.sock, cmd); err != nil {
		return
	}
	defer c.Close()
	// pipe
	outBuf, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	go c.ReadFrom(bytes.NewBufferString(sc))
	_, err = c.DemuxTo(outBuf, errBuf)
	stdout, stderr = outBuf.String(), errBuf.String()
	return
}

func (s *sandbox) ExecAttach(opts ExecAttachOptions) (err error) {
	// dial
	cmd := minit.Command{
		Cmd: opts.Command,
		Pty: opts.IsPty,
		Env: opts.Env,
	}
	if len(opts.Term) > 0 {
		if cmd.Env == nil {
			cmd.Env = []string{}
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", opts.Term))
	}
	if len(cmd.Cmd) == 0 {
		cmd.Cmd = []string{"/bin/bash"}
	}
	var c minit.Conn
	if c, err = minit.Dial("unix", s.sock, cmd); err != nil {
		return
	}
	defer c.Close()
	if cmd.Pty && opts.WindowChan != nil {
		go func() {
			for w := range opts.WindowChan {
				c.SetWinsize(uint16(w.Width), uint16(w.Height))
			}
		}()
	}
	go c.ReadFrom(opts.Stdin)
	_, err = c.DemuxTo(opts.Stdout, opts.Stderr)
	return
}
