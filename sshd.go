/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/sandbox"
	"ireul.com/bunker/types"
	"ireul.com/bunker/utils"
	"ireul.com/rec"
)

const (
	sshdBunkerUserAccount   = "bunker-user-account"
	sshdBunkerSandboxMode   = "bunker-sandbox-mode"
	sshdBunkerTargetUser    = "bunker-target-user"
	sshdBunkerTargetServer  = "bunker-target-server"
	sshdBunkerTargetAddress = "bunker-target-address"
)

var (
	// ErrSSHDAlreadyRunning SSHD instance is already running
	ErrSSHDAlreadyRunning = errors.New("sshd is already running")
)

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
		tu, th := utils.SSHDDecodeTargetServer(conn.User())
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
				sshdBunkerUserAccount:   u.Account,
				sshdBunkerTargetUser:    tu,
				sshdBunkerTargetServer:  r.Name,
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
	var targetServer = sconn.Permissions.Extensions[sshdBunkerTargetServer]
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
			utils.NewSandboxForwarder(sb, schn, sreq).Start(wg)
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

		var sess *models.Session
		if sess, err = s.db.CreateSession(userAccount, targetUser, targetServer); err != nil {
			tchn.Close()
			continue
		}

		if schn, sreq, err = nchn.Accept(); err != nil {
			tchn.Close()
			continue
		}

		// forward ssh channel
		utils.NewSSHForwarder(
			schn,
			sreq,
			tchn,
			treq,
			targetUser,
			createReplayFileWriter(filepath.Join(s.Config.SSHD.ReplayDir, sess.ReplayFile)),
		).SetPtyCallback(func() {
			s.db.Model(sess).Update(map[string]interface{}{"is_recorded": true})
		}).SetDoneCallback(func() {
			s.db.Model(sess).Update(map[string]interface{}{"ended_at": time.Now()})
		}).Start(wg)
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

func createReplayFileWriter(filename string) rec.Writer {
	return rec.NewWriter(gzip.NewWriter(utils.NewLazyFileWriter(filename)), rec.WriterOption{
		SqueezeFrame: 150,
	})
}
