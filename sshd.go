/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
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

type sshdCore struct {
	cfg          types.Config
	db           *models.DB
	clientSigner sshd.Signer
}

func (core *sshdCore) createSSHDHandler() sshd.Handler {
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
			l.Printf("  ssh 目标用户@目标服务器@%s\n", core.cfg.Domain)
		} else {
			var s *models.Server
			var err error
			if s, err = core.db.CheckGrant(u.ID, targetUser, targetHost); err != nil {
				l.Printf("你没有权限连接 %s@%s\n", targetUser, targetHost)
			} else {
				core.proxySSHDSession(sess, targetUser, s.Address)
				return
			}
		}
		l.Println()
		// print all available servers
		return
	}
}

func (core *sshdCore) createSSHDPublicKeyHandler() sshd.PublicKeyHandler {
	return func(c sshd.Context, key sshd.PublicKey) bool {
		var err error
		// find Key
		k := models.Key{}
		if err = core.db.First(&k, "fingerprint = ?", ssh.FingerprintSHA256(key)).Error; err != nil || k.ID == 0 {
			return false
		}
		// find User
		u := models.User{}
		if err = core.db.First(&u, k.UserID).Error; err != nil || u.ID == 0 || u.IsBlocked {
			return false
		}
		// touch
		core.db.Touch(&k, &u)
		// assign user account
		c.SetValue(sshdBunkerUser, u)
		return true
	}
}

func (core *sshdCore) proxySSHDSession(sess sshd.Session, targetUser string, targetAddress string) {
}

func createSSHDServer(cfg types.Config) (s *sshd.Server, err error) {
	// client signer and host signer
	var k []byte
	if k, err = ioutil.ReadFile(cfg.SSHD.PrivateKey); err != nil {
		return
	}
	var hostSigner ssh.Signer
	if hostSigner, err = ssh.ParsePrivateKey(k); err != nil {
		return
	}
	if k, err = ioutil.ReadFile(cfg.SSH.PrivateKey); err != nil {
		return
	}
	var clientSigner ssh.Signer
	if clientSigner, err = ssh.ParsePrivateKey(k); err != nil {
		return
	}
	// db
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	// context
	core := &sshdCore{cfg: cfg, db: db, clientSigner: clientSigner}
	s = &sshd.Server{
		Addr:             fmt.Sprintf("%s:%d", cfg.SSHD.Host, cfg.SSHD.Port),
		HostSigners:      []sshd.Signer{hostSigner},
		Handler:          core.createSSHDHandler(),
		PublicKeyHandler: core.createSSHDPublicKeyHandler(),
	}
	return
}
