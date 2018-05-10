/**
 * bunker.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"strings"

	"github.com/yankeguo/bunker/models"
	"github.com/yankeguo/bunker/types"
	"github.com/yankeguo/bunker/utils"
	"golang.org/x/crypto/ssh"
)

// VERSION version string of current source code
const VERSION = "1.0.0"

// Bunker the bunker server
type Bunker struct {
	Config types.Config
	http   *HTTP
	sshd   *SSHD
	auto   *Auto
	db     *models.DB
}

// NewBunker create a new bunker instance
func NewBunker(config types.Config) *Bunker {
	return &Bunker{Config: config}
}

func (b *Bunker) ensureDB() (err error) {
	if b.db == nil {
		if b.db, err = models.NewDB(b.Config); err != nil {
			return
		}
	}
	return
}

// ListenAndServe run the server
func (b *Bunker) ListenAndServe() (err error) {
	if b.http == nil {
		b.http = NewHTTP(b.Config)
	}
	if b.sshd == nil {
		b.sshd = NewSSHD(b.Config)
	}
	if b.auto == nil {
		b.auto = NewAuto(b.Config)
	}
	if err = b.ensureDB(); err != nil {
		return
	}
	// share the same *models.DB
	b.http.db = b.db
	b.sshd.db = b.db
	b.auto.db = b.db
	return utils.RunServers(b.http, b.sshd, b.auto)
}

// Migrate the database
func (b *Bunker) Migrate() (err error) {
	if err = b.ensureDB(); err != nil {
		return
	}
	return b.db.AutoMigrate()
}

// CreateUserOption option to create user
type CreateUserOption struct {
	Account   string
	Password  string
	PublicKey []byte // optional public key
	IsAdmin   bool
}

// CreateUser create a user
func (b *Bunker) CreateUser(option CreateUserOption) (err error) {
	if err = b.ensureDB(); err != nil {
		return
	}
	// create user
	u := &models.User{
		Account: option.Account,
		IsAdmin: utils.ToInt(option.IsAdmin),
	}
	if err = u.SetPassword(option.Password); err != nil {
		return
	}
	if err = b.db.Create(u).Error; err != nil {
		return
	}
	// create public key
	if len(option.PublicKey) > 0 {
		var p ssh.PublicKey
		if p, _, _, _, err = ssh.ParseAuthorizedKey(option.PublicKey); err != nil {
			return
		}
		k := &models.Key{
			Name:        "main",
			UserID:      u.ID,
			Fingerprint: strings.TrimSpace(ssh.FingerprintSHA256(p)),
		}
		if err = b.db.Create(k).Error; err != nil {
			return
		}
	}
	return
}

// ChangePasswordOption reset user password option
type ChangePasswordOption struct {
	Account  string
	Password string
}

// ChangePassword reset user password
func (b *Bunker) ChangePassword(option ChangePasswordOption) (err error) {
	if err = b.ensureDB(); err != nil {
		return
	}
	u := &models.User{}
	if err = u.SetPassword(option.Password); err != nil {
		return
	}
	err = b.db.Model(models.User{}).Where("account = ?", option.Account).Update(map[string]interface{}{
		"password_digest": u.PasswordDigest,
	}).Error
	return
}

// CreateServerOption option to create a server
type CreateServerOption struct {
	Name    string
	Address string
}

// CreateServer create a server
func (b *Bunker) CreateServer(option CreateServerOption) (err error) {
	if err = b.ensureDB(); err != nil {
		return
	}
	if err = b.db.Assign(map[string]interface{}{
		"address": option.Address,
	}).FirstOrCreate(&models.Server{}, map[string]interface{}{
		"name": option.Name,
	}).Error; err != nil {
		return
	}
	return
}

// Shutdown the internal servers
func (b *Bunker) Shutdown() (err error) {
	return utils.ShutdownServers(b.http, b.sshd)
}
