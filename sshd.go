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
	sshdTargetUserKey = "target-user"
	sshdTargetHostKey = "target-host"
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
		Handler:          sshdSessionHandler(db),
		PublicKeyHandler: sshdPublicKeyHandler(db),
	}
	return
}

func sshdSessionHandler(db *models.DB) sshd.Handler {
	return func(sess sshd.Session) {
		user := sess.Context().Value(sshdBunkerUserKey).(string)
		tuser := sess.Context().Value(sshdTargetUserKey).(string)
		thost := sess.Context().Value(sshdTargetHostKey).(string)
		log.Println("User:", user)
		log.Println("TargetUser:", tuser)
		log.Println("TargetHost:", thost)
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
		ctx.SetValue(sshdBunkerUserKey, u.Login)
		// decode target information
		cps := strings.Split(ctx.User(), "@")
		if len(cps) == 2 {
			ctx.SetValue(sshdTargetUserKey, cps[0])
			ctx.SetValue(sshdTargetHostKey, cps[1])
		} else {
			ctx.SetValue(sshdTargetUserKey, "")
			ctx.SetValue(sshdTargetHostKey, "")
		}
		return true
	}
}
