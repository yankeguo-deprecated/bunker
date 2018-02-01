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

func decodeSSHDUser(input string) (user string, host string) {
	ds := strings.Split(input, "@")
	if len(ds) == 2 {
		user = ds[0]
		host = ds[1]
	}
	return
}

func transformSSHDCommand(input []string, user string) []string {
	return append([]string{"sudo", "-u", user, "-i", "--"}, input...)
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
		tu, th := decodeSSHDUser(conn.User())
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
	// build client
	var ccfg = &ssh.ClientConfig{
		User: sconn.Permissions.Extensions[sshdBunkerTargetUser],
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.clientSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var client *ssh.Client
	if client, err = ssh.Dial("tcp", sconn.Permissions.Extensions[sshdBunkerTargetAddress], ccfg); err != nil {
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
			continue
		}

		wg.Add(2)
		go bridgeSSHRequestAndClose(tchn, sreq, wg)
		go bridgeSSHRequestAndClose(schn, treq, wg)

		go bridgeSSHStream(tchn, schn)
		go bridgeSSHStream(schn, tchn)
		go bridgeSSHStream(schn.Stderr(), tchn.Stderr())
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

func bridgeSSHRequestAndClose(chn ssh.Channel, reqs <-chan *ssh.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range reqs {
		ok, _ := chn.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
	chn.Close()
}

func bridgeSSHStream(dst io.Writer, src io.Reader) {
	if dst != nil && src != nil {
		io.Copy(dst, src)
	}
}
