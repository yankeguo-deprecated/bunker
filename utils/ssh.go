/**
 * ssh.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/sandbox"
	"ireul.com/rec"
	"ireul.com/shellquote"
)

// CheckSSHLocalIP check ssh local ip
func CheckSSHLocalIP(conn ssh.ConnMetadata, ip string) bool {
	hostIP := net.ParseIP(ip)
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return addr.IP.Equal(hostIP)
	}
	return false
}

// SSHForwarderPtyCallback pty is detected
type SSHForwarderPtyCallback func()

// SSHForwarderDoneCallback pty is detected
type SSHForwarderDoneCallback func()

// SSHConfigEntry ssh config entry
type SSHConfigEntry struct {
	Name    string
	Address string
}

// ParseSSHConfig parse ssh config
func ParseSSHConfig(c []byte) []SSHConfigEntry {
	ret := []SSHConfigEntry{}
	ls := ParseSSHLines(c)
	var host string
	var hostname string
	var port string
	var add = func() {
		// already has a host recorded
		if len(host) > 0 {
			if len(hostname) > 0 {
				if len(port) == 0 {
					port = "22"
				}
				ret = append(ret, SSHConfigEntry{
					Name:    host,
					Address: fmt.Sprintf("%s:%s", hostname, port),
				})
			}
		}
		host = ""
		hostname = ""
		port = ""
	}
	for _, l := range ls {
		if l[0] == "host" {
			add()
			host = l[1]
		}
		if l[0] == "hostname" {
			hostname = l[1]
		}
		if l[0] == "port" {
			port = l[1]
		}
	}
	add()
	return ret
}

// ParseSSHLines parse ssh lines
func ParseSSHLines(c []byte) [][]string {
	ret := [][]string{}
	var err error
	r := bufio.NewReader(bytes.NewReader(c))
	for {
		var l []byte
		l, _, err = r.ReadLine()
		if err != nil {
			break
		}
		ls := strings.TrimSpace(string(l))
		lss := strings.SplitN(ls, " ", 2)
		if len(lss) != 2 {
			lss = strings.SplitN(ls, "\t", 2)
			if len(lss) != 2 {
				continue
			}
		}
		ret = append(ret, []string{
			strings.ToLower(strings.TrimSpace(lss[0])),
			strings.TrimSpace(lss[1]),
		})
	}
	return ret
}

// ParseWchanRequest parse window change request
func ParseWchanRequest(s []byte) (win sandbox.Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = sandbox.Window{
		Width:  uint(width32),
		Height: uint(height32),
	}
	return
}

// ParsePtyRequest parse pty request
func ParsePtyRequest(s []byte) (pty sandbox.Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	pty = sandbox.Pty{
		Term: term,
		Window: sandbox.Window{
			Width:  uint(width32),
			Height: uint(height32),
		},
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

// SSHDDecodeTargetServer sshd decode target user and server
func SSHDDecodeTargetServer(input string) (user string, host string) {
	ds := strings.Split(input, "@")
	if len(ds) == 2 {
		user = ds[0]
		host = ds[1]
	}
	return
}

// SSHDModifyCommand sshd modify target command with sudo
func SSHDModifyCommand(user string, input string) string {
	if len(input) > 0 {
		return shellquote.Join("sudo", "-S", "-n", "-u", user, "-i", "--", "bash", "-c", input)
	}
	return shellquote.Join("sudo", "-S", "-n", "-u", user, "-i")
}

// SSHForwarder forward two ssh connection
type SSHForwarder struct {
	schn  ssh.Channel
	sreq  <-chan *ssh.Request
	tchn  ssh.Channel
	treq  <-chan *ssh.Request
	tuser string
	rw    rec.Writer
	pcb   SSHForwarderPtyCallback
	dcb   SSHForwarderDoneCallback
}

// NewSSHForwarder new ssh forwarder
func NewSSHForwarder(schn ssh.Channel, sreq <-chan *ssh.Request, tchn ssh.Channel, treq <-chan *ssh.Request, tuser string, rw rec.Writer) *SSHForwarder {
	return &SSHForwarder{
		schn:  schn,
		sreq:  sreq,
		tchn:  tchn,
		treq:  treq,
		tuser: tuser,
		rw:    rw,
	}
}

// SetPtyCallback set pty callback
func (f *SSHForwarder) SetPtyCallback(pcb SSHForwarderPtyCallback) *SSHForwarder {
	f.pcb = pcb
	return f
}

// SetDoneCallback set pty callback
func (f *SSHForwarder) SetDoneCallback(dcb SSHForwarderDoneCallback) *SSHForwarder {
	f.dcb = dcb
	return f
}

// Start start forwarding with sync.WaitGroup
func (f *SSHForwarder) Start(gwg *sync.WaitGroup) {
	gwg.Add(2)
	go f.ForwardTarget(gwg)
	go f.ForwardSource(gwg)
}

// ForwardTarget forward target connection to source connection
func (f *SSHForwarder) ForwardTarget(gwg *sync.WaitGroup) {
	defer gwg.Done()
	// ensure stdout, stderr and target chan *ssh.Request are all finished
	wg := &sync.WaitGroup{}
	wg.Add(3)
	go f.forwardStdout(wg)
	go f.forwardStderr(wg)
	go f.forwardTargetRequests(wg)
	wg.Wait()
	// close source channel, because target channel is totally finished
	f.schn.Close()
	// close replay writer
	f.rw.Close()
	// call done callback
	if f.dcb != nil {
		go f.dcb()
	}
}

// ForwardSource forward source connection to target connection
func (f *SSHForwarder) ForwardSource(gwg *sync.WaitGroup) {
	defer gwg.Done()
	// ensure stdin, source chan *ssh.Request are all finished
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go f.forwardStdin(wg)
	go f.forwardSourceRequests(wg)
	wg.Wait()
	// close target channel, because source channel is totally finished
	f.tchn.Close()
}

func (f *SSHForwarder) forwardSourceRequests(wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range f.sreq {
		// transform exec, shell request with targetUser
		switch req.Type {
		case "exec":
			// transform "exec" with sudo prefix
			var pl = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &pl)
			pl.Value = SSHDModifyCommand(f.tuser, pl.Value)
			req.Payload = ssh.Marshal(&pl)
		case "shell":
			// transform "shell" to "exec" with sudo prefix
			var pl = struct{ Value string }{
				Value: SSHDModifyCommand(f.tuser, ""),
			}
			req.Type = "exec"
			req.Payload = ssh.Marshal(&pl)
		}
		// ban "x11-req", "subsystem", "env" requests, cause they may escape from sudo
		switch req.Type {
		case "x11-req", "subsystem", "env":
			req.Reply(false, nil)
		default:
			ok, _ := f.tchn.SendRequest(req.Type, req.WantReply, req.Payload)
			req.Reply(ok, nil)
		}
		// initialize replayWriter if pty-request is found
		switch req.Type {
		case "pty-req":
			f.rw.Activate()
			w, ok := ParsePtyRequest(req.Payload)
			if ok {
				f.rw.WriteWindowSize(uint32(w.Window.Width), uint32(w.Window.Height))
			}
			if f.pcb != nil {
				go f.pcb()
			}
		case "window-change":
			w, ok := ParseWchanRequest(req.Payload)
			if ok {
				f.rw.WriteWindowSize(uint32(w.Width), uint32(w.Height))
			}
		}
	}
}

func (f *SSHForwarder) forwardTargetRequests(wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range f.treq {
		ok, _ := f.schn.SendRequest(req.Type, req.WantReply, req.Payload)
		req.Reply(ok, nil)
	}
}

func (f *SSHForwarder) forwardStdin(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(f.tchn, f.schn)
	f.tchn.CloseWrite()
}

func (f *SSHForwarder) forwardStdout(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(io.MultiWriter(f.schn, NewSilentWriter(f.rw.Stdout())), f.tchn)
	f.schn.CloseWrite()
}

func (f *SSHForwarder) forwardStderr(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(io.MultiWriter(f.schn.Stderr(), NewSilentWriter(f.rw.Stderr())), f.tchn.Stderr())
}

// SandboxForwarder sandbox ssh forwarder
type SandboxForwarder struct {
	schn      ssh.Channel
	sreq      <-chan *ssh.Request
	sb        sandbox.Sandbox
	env       []string
	cmd       []string
	pty       *sandbox.Pty
	isHandled bool
	wch       chan sandbox.Window
}

// NewSandboxForwarder new sandbox forwarder
func NewSandboxForwarder(sb sandbox.Sandbox, scnh ssh.Channel, sreq <-chan *ssh.Request) *SandboxForwarder {
	return &SandboxForwarder{
		schn: scnh,
		sreq: sreq,
		sb:   sb,
	}
}

// Start start on sync.WaitGroup
func (f *SandboxForwarder) Start(gwg *sync.WaitGroup) {
	gwg.Add(1)
	go f.Run(gwg)
}

// Run run on sync.WaitGroup
func (f *SandboxForwarder) Run(gwg *sync.WaitGroup) {
	defer gwg.Done()
	for req := range f.sreq {
		switch req.Type {
		case "shell", "exec":
			{
				// already handled
				if f.isHandled {
					req.Reply(false, nil)
					continue
				}
				f.isHandled = true
				req.Reply(true, nil)
				// extract command
				var pl struct{ Value string }
				ssh.Unmarshal(req.Payload, &pl)
				f.cmd, _ = shellquote.Split(pl.Value)
				// handle
				go f.handle()
			}
		case "env":
			{
				// already handled
				if f.isHandled {
					req.Reply(false, nil)
					continue
				}
				// append env
				var kv struct{ Key, Value string }
				ssh.Unmarshal(req.Payload, &kv)
				if f.env == nil {
					f.env = make([]string, 0)
				}
				f.env = append(f.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
				req.Reply(true, nil)
			}
		case "pty-req":
			{
				if f.isHandled || f.pty != nil {
					req.Reply(false, nil)
					continue
				}
				pty, ok := ParsePtyRequest(req.Payload)
				if !ok {
					req.Reply(false, nil)
					continue
				}
				f.pty = &pty
				f.wch = make(chan sandbox.Window, 1)
				f.wch <- pty.Window
				defer close(f.wch)
				req.Reply(true, nil)
			}
		case "window-change":
			{
				if f.pty == nil {
					req.Reply(false, nil)
					continue
				}
				w, ok := ParseWchanRequest(req.Payload)
				if !ok {
					req.Reply(false, nil)
					continue
				}
				f.pty.Window = w
				f.wch <- w
				req.Reply(true, nil)
			}
		default:
			req.Reply(false, nil)
		}
	}
}

func (f *SandboxForwarder) handle() {
	var opts = sandbox.ExecAttachOptions{
		Env:     f.env,
		Command: f.cmd,
		Stdin:   f.schn,
		Stdout:  f.schn,
		Stderr:  f.schn.Stderr(),
	}
	if f.pty != nil {
		opts.IsPty = true
		opts.Term = f.pty.Term
		opts.WindowChan = f.wch
	}
	pl := make([]byte, 4)
	if err := f.sb.ExecAttach(opts); err != nil {
		binary.BigEndian.PutUint32(pl, 1)
	}
	f.schn.SendRequest("exit-status", false, pl)
	f.schn.Close()
}
