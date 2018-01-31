/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/sshd"
)

const (
	sshdBunkerUser = "bunker-user"
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

// SSHDSession session of a sshd connection
type SSHDSession struct {
	sshd.Session
	config       types.Config
	clientSigner ssh.Signer
	db           *models.DB
	logger       *log.Logger
	user         models.User
	targetUser   string
	targetHost   string
	pty          sshd.Pty
	isPty        bool
	wchan        <-chan sshd.Window
}

// NewSSHDSession create a new sshd session
func NewSSHDSession(sshd *SSHD, sess sshd.Session) *SSHDSession {
	s := &SSHDSession{
		Session:      sess,
		config:       sshd.Config,
		clientSigner: sshd.clientSigner,
		db:           sshd.db,
		logger:       log.New(sess, "bunker: ", 0),
		user:         sess.Context().Value(sshdBunkerUser).(models.User),
	}
	s.targetUser, s.targetHost = decodeSSHDUser(sess.User())
	s.pty, s.wchan, s.isPty = sess.Pty()
	return s
}

// Printf same as fmt.Printf
func (s *SSHDSession) Printf(f string, v ...interface{}) {
	s.logger.Printf(f, v...)
}

// PtyPrintf Printf if isPty
func (s *SSHDSession) PtyPrintf(f string, v ...interface{}) {
	if s.isPty {
		s.Printf(f, v...)
	}
}

// Println same as fmt.Println
func (s *SSHDSession) Println(v ...interface{}) {
	s.logger.Println(v...)
}

// PtyPrintln Println if isPty
func (s *SSHDSession) PtyPrintln(v ...interface{}) {
	if s.isPty {
		s.logger.Println(v...)
	}
}

func (s *SSHDSession) createHostKeyCallback(srv models.Server) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}
}

// Run run the sshd session
func (s *SSHDSession) Run() {
	s.PtyPrintf("欢迎使用 bunker v%s，用户: %s\n", VERSION, s.user.Account)
	// check information
	if len(s.targetUser) == 0 || len(s.targetHost) == 0 {
		s.Printf("没有指定目标服务器或目标账户，参考格式: \"ssh 目标账户@目标服务器@%s\"\n", s.config.Domain)
		s.Exit(1)
		return
	}
	// find server
	var srv models.Server
	var err error
	if err = s.db.First(&srv, "name = ?", s.targetHost).Error; srv.ID == 0 || err != nil {
		s.Println("没有找到目标服务器，或者没有目标账户访问权限")
		s.Exit(1)
		return
	}
	// check authentication
	if err = s.db.CheckGrant(s.user, srv, s.targetUser); err != nil {
		s.Println("没有找到目标服务器，或者没有目标账户访问权限")
		s.Exit(1)
		return
	}
	// create ssh client
	var client *ssh.Client
	if client, err = ssh.Dial("tcp", srv.Address, &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.clientSigner),
		},
		HostKeyCallback: s.createHostKeyCallback(srv),
	}); err != nil {
		s.Println("无法连接目标服务器，连接失败:", err)
		s.Exit(1)
		return
	}
	defer client.Close()
	// create ssh session
	var cs *ssh.Session
	if cs, err = client.NewSession(); err != nil {
		s.Println("无法连接目标服务器，无法建立 Session:", err)
		s.Exit(1)
		return
	}
	defer cs.Close()
	// pipe ssh session
	cs.Stdin = s
	cs.Stdout = s
	cs.Stderr = s.Stderr()
	for range s.Environ() {
		// TODO: proxy environment
	}
	if s.isPty {
		if err = cs.RequestPty(s.pty.Term, s.pty.Window.Height, s.pty.Window.Width, nil); err != nil {
			s.Println("无法连接目标服务器，无法请求 PTY:", err)
			s.Exit(1)
			return
		}
		go func() {
			for w := range s.wchan {
				cs.WindowChange(w.Height, w.Width)
			}
		}()
	}
}

// SSHD sshd instance
type SSHD struct {
	Config       types.Config
	server       *sshd.Server
	db           *models.DB
	clientSigner ssh.Signer
	hostSigner   ssh.Signer
}

// NewSSHD create a SSHD instance
func NewSSHD(config types.Config) *SSHD {
	return &SSHD{Config: config}
}

// CreatePublicKeyCallback creates the PublicKeyCallback for ssh.ServerConfig
func (s *SSHD) CreatePublicKeyCallback() interface{} {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}
}

// Handle handles a ssh.ServerConn, should run in a seperated goroutine
func (s *SSHD) Handle(conn *ssh.ServerConn) error {
	return nil
}

func (s *SSHD) createHandler() sshd.Handler {
	return func(sess sshd.Session) {
		NewSSHDSession(s, sess).Run()
	}
}

func (s *SSHD) createPublicKeyHandler() sshd.PublicKeyHandler {
	return func(c sshd.Context, key sshd.PublicKey) bool {
		var err error
		// find Key
		k := models.Key{}
		if err = s.db.First(&k, "fingerprint = ?", ssh.FingerprintSHA256(key)).Error; err != nil || k.ID == 0 {
			return false
		}
		// find User
		u := models.User{}
		if err = s.db.First(&u, k.UserID).Error; err != nil || u.ID == 0 || u.IsBlocked {
			return false
		}
		// touch
		s.db.Touch(&k, &u)
		// assign user account
		c.SetValue(sshdBunkerUser, u)
		return true
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
	if s.server == nil {
		s.server = &sshd.Server{
			Addr:             fmt.Sprintf("%s:%d", s.Config.SSHD.Host, s.Config.SSHD.Port),
			HostSigners:      []sshd.Signer{s.hostSigner},
			Handler:          s.createHandler(),
			PublicKeyHandler: s.createPublicKeyHandler(),
		}
	}
	err = s.server.ListenAndServe()
	if err == sshd.ErrServerClosed {
		err = nil
	}
	return
}

// Shutdown shutdown the sshd instance
func (s *SSHD) Shutdown() (err error) {
	if s.server != nil {
		return s.server.Shutdown(context.Background())
	}
	return
}
