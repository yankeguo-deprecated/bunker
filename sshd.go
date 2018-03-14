/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/sandbox"
	"ireul.com/bunker/types"
	"ireul.com/shellquote"
)

const (
	sshdBunkerUserAccount   = "bunker-user-account"
	sshdBunkerSandboxMode   = "bunker-sandbox-mode"
	sshdBunkerTargetUser    = "bunker-target-user"
	sshdBunkerTargetAddress = "bunker-target-address"
)

var (
	// ErrSSHDAlreadyRunning SSHD instance is already running
	ErrSSHDAlreadyRunning = errors.New("sshd is already running")
)

func sshdDecodeTargetServer(input string) (user string, host string) {
	ds := strings.Split(input, "@")
	if len(ds) == 2 {
		user = ds[0]
		host = ds[1]
	}
	return
}

func sshdModifyCommand(user string, input string) string {
	if len(input) > 0 {
		return shellquote.Join("sudo", "-S", "-n", "-u", user, "-i", "--", "bash", "-c", input)
	}
	return shellquote.Join("sudo", "-S", "-n", "-u", user, "-i")
}

// SSHD sshd instance
type SSHD struct {
	Config          types.Config
	db              *models.DB
	sshServerConfig *ssh.ServerConfig
	clientSigner    ssh.Signer
	hostSigner      ssh.Signer
	listener        net.Listener
	sandboxManager  sandbox.Manager
}

// NewSSHD create a SSHD instance
func NewSSHD(config types.Config) *SSHD {
	return &SSHD{Config: config}
}

func (s *SSHD) createHostKeyCallback(r models.Server) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}
}

func (s *SSHD) createPublicKeyCallback() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		var err error
		// fetch target information
		tu, th := sshdDecodeTargetServer(conn.User())
		// find Key
		k := models.Key{}
		fp := ssh.FingerprintSHA256(key)
		if err = s.db.First(&k, "fingerprint = ?", fp).Error; err != nil || k.ID == 0 {
			return nil, fmt.Errorf("unknown key with fingerprint %s", fp)
		}
		// find User
		u := models.User{}
		if err = s.db.First(&u, k.UserID).Error; err != nil || u.ID == 0 || u.IsBlocked {
			return nil, fmt.Errorf("unknown user or blocked user")
		}
		s.db.Touch(&k, &u)
		// $SANDBOX SUPPORT$
		if len(tu) == 0 || len(th) == 0 {
			if k.IsSandbox {
				return nil, fmt.Errorf("cannot connect sandbox with sandbox key")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					sshdBunkerUserAccount: u.Account,
					sshdBunkerSandboxMode: "YES",
				},
			}, nil
		}
		// find Server
		r := models.Server{}
		if err = s.db.First(&r, "name = ?", th).Error; err != nil || r.ID == 0 {
			return nil, fmt.Errorf("target host not found with name \"%s\"", th)
		}
		// check auth
		if err = s.db.CheckGrant(u, r, tu); err != nil {
			return nil, fmt.Errorf("no permission to connect %s@%s", tu, th)
		}
		s.db.Touch(&r)
		return &ssh.Permissions{
			Extensions: map[string]string{
				sshdBunkerTargetUser:    tu,
				sshdBunkerTargetAddress: r.Address,
			},
		}, nil
	}
}

// ListenAndServe invoke internal sshd.Server#ListenAndServe, sshd.ErrServerClosed will be muted
func (s *SSHD) ListenAndServe() (err error) {
	var k []byte
	if s.sandboxManager == nil {
		if s.sandboxManager, err = sandbox.NewManager(s.Config); err != nil {
			return
		}
	}
	if s.clientSigner == nil {
		if k, err = ioutil.ReadFile(s.Config.SSH.PrivateKey); err != nil {
			return
		}
		if s.clientSigner, err = ssh.ParsePrivateKey(k); err != nil {
			return
		}
	}
	if s.hostSigner == nil {
		if k, err = ioutil.ReadFile(s.Config.SSHD.PrivateKey); err != nil {
			return
		}
		if s.hostSigner, err = ssh.ParsePrivateKey(k); err != nil {
			return
		}
	}
	if s.db == nil {
		if s.db, err = models.NewDB(s.Config); err != nil {
			return
		}
	}
	if s.sshServerConfig == nil {
		s.sshServerConfig = &ssh.ServerConfig{
			PublicKeyCallback: s.createPublicKeyCallback(),
		}
		s.sshServerConfig.AddHostKey(s.hostSigner)
	}
	if s.listener != nil {
		return ErrSSHDAlreadyRunning
	}
	if s.listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.Config.SSHD.Host, s.Config.SSHD.Port)); err != nil {
		return
	}
	for {
		var conn net.Conn
		if conn, err = s.listener.Accept(); err != nil {
			break
		}
		go s.handleRawConn(conn)
	}
	s.listener = nil
	if err == io.EOF {
		return nil
	}
	return
}

func (s *SSHD) updateSandboxPublicKey(sb sandbox.Sandbox, account string) (err error) {
	var ak string
	if ak, err = sb.GetSSHPublicKey(); err != nil {
		return
	}
	var pk ssh.PublicKey
	if pk, _, _, _, err = ssh.ParseAuthorizedKey([]byte(ak)); err != nil {
		return
	}
	return s.db.UpdateSandboxPublicKeyForAccount(ssh.FingerprintSHA256(pk), account)
}

func (s *SSHD) updateSandboxSSHConfig(sb sandbox.Sandbox, account string) (err error) {
	u := models.User{}
	if err = s.db.First(&u, "account = ?", account).Error; err != nil || u.ID == 0 {
		err = fmt.Errorf("user with account %s not found", account)
		return
	}
	cg := s.db.GetCombinedGrants(u.ID)
	se := make([]sandbox.SSHEntry, 0)
	for _, c := range cg {
		se = append(se, sandbox.SSHEntry{
			Name: fmt.Sprintf("%s-%s", c.ServerName, c.TargetUser),
			Host: s.Config.Domain,
			Port: uint(s.Config.SSHD.Port),
			User: fmt.Sprintf("%s@%s", c.TargetUser, c.ServerName),
		})
	}
	_, _, err = sb.ExecScript(sandbox.ScriptSeedSSHConfig(se))
	return
}

func (s *SSHD) handleRawConn(c net.Conn) {
	var err error
	// upgrade connection
	var sconn *ssh.ServerConn
	var cchan <-chan ssh.NewChannel
	var rchan <-chan *ssh.Request
	if sconn, cchan, rchan, err = ssh.NewServerConn(c, s.sshServerConfig); err != nil {
		return
	}
	defer sconn.Close()
	// discard global requests
	go ssh.DiscardRequests(rchan)
	// extract parameters
	var userAccount = sconn.Permissions.Extensions[sshdBunkerUserAccount]
	var targetUser = sconn.Permissions.Extensions[sshdBunkerTargetUser]
	var sandboxMode = sconn.Permissions.Extensions[sshdBunkerSandboxMode]
	var targetAddress = sconn.Permissions.Extensions[sshdBunkerTargetAddress]
	// $SANDBOX SUPPORT$
	if len(sandboxMode) > 0 {
		// ensure sandbox
		var sb sandbox.Sandbox
		if sb, err = s.sandboxManager.FindOrCreate(userAccount); err != nil {
			return
		}
		// update database from sandbox public key, ignore error
		s.updateSandboxPublicKey(sb, userAccount)
		// update sandbox .ssh/config
		s.updateSandboxSSHConfig(sb, userAccount)
		// range channels
		wg := &sync.WaitGroup{}
		for nchn := range cchan {
			// shadow var err error
			var err error
			// 'session' only
			if nchn.ChannelType() != "session" {
				nchn.Reject(ssh.UnknownChannelType, "only channel type \"session\" is allowed")
				continue
			}
			// accept channel
			var schn ssh.Channel
			var sreq <-chan *ssh.Request
			if schn, sreq, err = nchn.Accept(); err != nil {
				continue
			}
			// forward
			sshForwardSandbox(sb, schn, sreq, wg)
		}
		wg.Wait()
		return
	}
	// build client
	var ccfg = &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.clientSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var client *ssh.Client
	if client, err = ssh.Dial("tcp", targetAddress, ccfg); err != nil {
		return
	}
	defer client.Close()
	// bridge channels
	wg := &sync.WaitGroup{}
	for nchn := range cchan {
		// shadow var err error
		var err error
		// filter-out non 'session' channel
		if nchn.ChannelType() != "session" {
			nchn.Reject(ssh.UnknownChannelType, "only channel type \"session\" is allowed")
			continue
		}
		// bridge channel
		var schn ssh.Channel
		var sreq <-chan *ssh.Request
		var tchn ssh.Channel
		var treq <-chan *ssh.Request

		if tchn, treq, err = client.OpenChannel(nchn.ChannelType(), nchn.ExtraData()); err != nil {
			jerr := err.(*ssh.OpenChannelError)
			nchn.Reject(jerr.Reason, jerr.Message)
			continue
		}
		if schn, sreq, err = nchn.Accept(); err != nil {
			tchn.Close()
			continue
		}
		// forward ssh channel
		sshForwardChannel(schn, sreq, tchn, treq, targetUser, wg)
	}
	wg.Wait()
}

// Shutdown shutdown the sshd instance
func (s *SSHD) Shutdown() (err error) {
	if s.listener != nil {
		return s.listener.Close()
	}
	return
}

type sandboxForwarder struct {
	schn      ssh.Channel
	sreq      <-chan *ssh.Request
	sb        sandbox.Sandbox
	env       []string
	cmd       []string
	pty       *sandbox.Pty
	isHandled bool
	wch       chan sandbox.Window
}

func (f *sandboxForwarder) forward(gwg *sync.WaitGroup) {
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

func (f *sandboxForwarder) handle() {
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

func sshForwardSandbox(sb sandbox.Sandbox, schn ssh.Channel, sreq <-chan *ssh.Request, gwg *sync.WaitGroup) {
	gwg.Add(1)
	f := &sandboxForwarder{
		schn: schn,
		sreq: sreq,
		sb:   sb,
	}
	go f.forward(gwg)
}

type sshForwarder struct {
	schn  ssh.Channel
	sreq  <-chan *ssh.Request
	tchn  ssh.Channel
	treq  <-chan *ssh.Request
	tuser string
}

func sshForwardChannel(schn ssh.Channel, sreq <-chan *ssh.Request, tchn ssh.Channel, treq <-chan *ssh.Request, tuser string, gwg *sync.WaitGroup) {
	gwg.Add(2)
	f := &sshForwarder{
		schn:  schn,
		sreq:  sreq,
		tchn:  tchn,
		treq:  treq,
		tuser: tuser,
	}
	go f.forwardTarget(gwg)
	go f.forwardSource(gwg)
}

func (f *sshForwarder) forwardTarget(gwg *sync.WaitGroup) {
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
}

func (f *sshForwarder) forwardSource(gwg *sync.WaitGroup) {
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

func (f *sshForwarder) forwardSourceRequests(wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range f.sreq {
		// transform exec, shell request with targetUser
		switch req.Type {
		case "exec":
			// transform "exec" with sudo prefix
			var pl = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &pl)
			pl.Value = sshdModifyCommand(f.tuser, pl.Value)
			req.Payload = ssh.Marshal(&pl)
		case "shell":
			// transform "shell" to "exec" with sudo prefix
			var pl = struct{ Value string }{
				Value: sshdModifyCommand(f.tuser, ""),
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
	}
}

func (f *sshForwarder) forwardTargetRequests(wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range f.treq {
		ok, _ := f.schn.SendRequest(req.Type, req.WantReply, req.Payload)
		req.Reply(ok, nil)
	}
}

func (f *sshForwarder) forwardStdin(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(f.tchn, f.schn)
	f.tchn.CloseWrite()
}

func (f *sshForwarder) forwardStdout(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(f.schn, f.tchn)
	f.schn.CloseWrite()
}

func (f *sshForwarder) forwardStderr(wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(f.schn.Stderr(), f.tchn.Stderr())
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
