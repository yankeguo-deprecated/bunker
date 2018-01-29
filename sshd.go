/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/sshd"
)

const (
	sshdBunkerUser = "bunker-user"
)

func decodeTargetUserHost(input string) (user string, host string) {
	ds := strings.Split(input, "@")
	if len(ds) == 2 {
		user = ds[0]
		host = ds[1]
	}
	return
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

func (s *SSHD) createHandler() sshd.Handler {
	return func(sess sshd.Session) {
		// logger to session connection
		l := log.New(sess, "bunker: ", 0)
		// get the user
		u := sess.Context().Value(sshdBunkerUser).(models.User)
		l.Printf("欢迎使用 bunker v%s, 用户: %s\n", VERSION, u.Account)
		l.Println()
		// check target format
		targetUser, targetHost := decodeTargetUserHost(sess.User())
		if len(targetUser) == 0 || len(targetHost) == 0 {
			l.Println("你没有指定要连接的目标用户或目标服务器，请参考以下格式:")
			l.Println()
			l.Printf("  ssh 目标用户@目标服务器@%s\n", s.Config.Domain)
		} else {
			var srv *models.Server
			var err error
			if srv, err = s.db.CheckGrant(u.ID, targetUser, targetHost); err != nil {
				l.Printf("你没有权限连接 %s@%s\n", targetUser, targetHost)
			} else {
				l.Println(srv)
				return
			}
		}
		l.Println()
		// print all available servers
		return
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

func transformSSHDCommand(input []string, user string) []string {
	return append([]string{"sudo", "-u", user, "-i", "--"}, input...)
}
