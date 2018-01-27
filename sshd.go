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
	sshdBunkerUserKey = "bunker-user"
)

func createSSHDServer(cfg types.Config) (s *sshd.Server, err error) {
	var k []byte
	if k, err = ioutil.ReadFile(cfg.SSHD.PrivateKey); err != nil {
		return
	}
	var n ssh.Signer
	if n, err = ssh.ParsePrivateKey(k); err != nil {
		return
	}
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	s = &sshd.Server{
		Addr:             fmt.Sprintf("%s:%d", cfg.SSHD.Host, cfg.SSHD.Port),
		HostSigners:      []sshd.Signer{n},
		Handler:          sshdSessionHandler(cfg, db),
		PublicKeyHandler: sshdPublicKeyHandler(db),
	}
	return
}

func sshdSessionHandler(cfg types.Config, db *models.DB) sshd.Handler {
	return func(sess sshd.Session) {
		u := sess.Context().Value(sshdBunkerUserKey).(models.User)
		l := log.New(sess, "bunker: ", 0)
		l.Printf("欢迎使用 bunker v%s, 用户: %s\n", VERSION, u.Login)
		ds := strings.Split(sess.User(), "@")
		if len(ds) != 2 {
			l.Println()
			l.Println("你没有指定要连接的目标用户和服务器，请参考以下格式:")
			l.Println()
			l.Printf("  ssh 目标用户@目标服务器@%s\n", cfg.Domain)
			l.Println()
			l.Println("当前可以连接的服务器:")
			return
		}
	}
}

func sshdPublicKeyHandler(db *models.DB) sshd.PublicKeyHandler {
	return func(ctx sshd.Context, key sshd.PublicKey) bool {
		var err error
		// find Key
		k := models.Key{}
		if err = db.First(&k, "fingerprint = ?", ssh.FingerprintSHA256(key)).Error; err != nil {
			log.Println("internal error:", err)
			return false
		}
		if k.ID == 0 {
			return false
		}
		// find User
		u := models.User{}
		if err = db.First(&u, k.UserID).Error; err != nil {
			log.Println("internal error:", err)
			return false
		}
		if u.ID == 0 || u.IsBlocked {
			return false
		}
		// assign user login
		ctx.SetValue(sshdBunkerUserKey, u)
		return true
	}
}
