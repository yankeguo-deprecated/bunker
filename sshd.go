/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/shellquote"
)

const (
	sshdBunkerUser          = "bunker-user"
	sshdBunkerTargetUser    = "bunker-target-user"
	sshdBunkerTargetAddress = "bunker-target-address"
)

var (
	// ErrSSHDAlreadyRunning SSHD instance is already running
	ErrSSHDAlreadyRunning = errors.New("sshd is already running")
)

func sshdDecodeUser(input string) (user string, host string) {
	ds := strings.Split(input, "@")
	if len(ds) == 2 {
		user = ds[0]
		host = ds[1]
	}
	return
}

func sshdModifyCommand(user string, input string) string {
	if len(input) > 0 {
		return shellquote.Join("sudo", "-n", "-u", user, "-i", "--", "bash", "-c", input)
	}
	return shellquote.Join("sudo", "-n", "-u", user, "-i")
}

// SSHD sshd instance
type SSHD struct {
	Config          types.Config
	db              *models.DB
	sshServerConfig *ssh.ServerConfig
	clientSigner    ssh.Signer
	hostSigner      ssh.Signer
	listener        net.Listener
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
		tu, th := sshdDecodeUser(conn.User())
		if len(tu) == 0 || len(th) == 0 {
			return nil, fmt.Errorf("invalid target information, example: \"ssh [TARGET_USER]@[TARGET_HOST]@%s\"", s.Config.Domain)
		}
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
	// extract parameters
	var targetUser = sconn.Permissions.Extensions[sshdBunkerTargetUser]
	var targetAddress = sconn.Permissions.Extensions[sshdBunkerTargetAddress]
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
	// discard global requests
	go ssh.DiscardRequests(rchan)
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
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			ok, _ := f.tchn.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}
}

func (f *sshForwarder) forwardTargetRequests(wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range f.treq {
		ok, _ := f.schn.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok, nil)
		}
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
