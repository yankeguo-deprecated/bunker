/**
 * models/db.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yankeguo/bunker/types"
	"github.com/yankeguo/bunker/utils"
	"landzero.net/x/com"
	"landzero.net/x/database/orm"
	_ "landzero.net/x/database/sqlite3" // sqlite3 adapter
)

// NamePattern general name pattern
var NamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\._\-]{3,}$`)

// WildcardPattern wildcard pattern
var WildcardPattern = regexp.MustCompile(`^[a-zA-Z0-9\._\*\-]*$`)

// Model basic model, not using orm.Model, no deletedAt
type Model struct {
	ID        uint      `orm:"primary_key" json:"id"` // id
	CreatedAt time.Time `orm:"" json:"createdAt"`     // created at
	UpdatedAt time.Time `orm:"" json:"updatedAt"`     // updated at
}

// DB wrapper for orm.DB
type DB struct {
	*orm.DB
}

// NewDB create a new database from Config struct
func NewDB(cfg types.Config) (db *DB, err error) {
	var d *orm.DB
	if d, err = orm.Open("sqlite3", cfg.DB.File); err != nil {
		return
	}
	d = d.LogMode(cfg.Env != "production")
	db = &DB{d}
	return
}

// AutoMigrate automatically migrate all models
func (w *DB) AutoMigrate() error {
	return w.DB.AutoMigrate(
		Server{},
		User{},
		Key{},
		Grant{},
		Session{},
	).Error
}

// Touch update the UsedAt field
func (w *DB) Touch(ms ...interface{}) {
	n := time.Now()
	for _, m := range ms {
		w.Model(m).UpdateColumn("UsedAt", n)
	}
}

// FindUserByLogin find user by account and password
func (w *DB) FindUserByLogin(account string, password string) (*User, error) {
	u := User{}
	if err := w.First(&u, "account = ?", account).Error; err != nil || u.ID == 0 || !u.CheckPassword(password) {
		return nil, errors.New("invalid credentials")
	}
	return &u, nil
}

// CheckGrant check target grant
func (w *DB) CheckGrant(u User, s Server, targetUser string) (err error) {
	gs := []Grant{}
	w.Find(&gs, "user_id = ? AND target_user = ? AND (expires_at IS NULL OR expires_at > ?)", u.ID, targetUser, time.Now())
	for _, g := range gs {
		if com.MatchAsterisk(g.ServerName, s.Name) {
			return nil
		}
	}
	return fmt.Errorf("Grant not find")
}

// CountUserSSHKeys count user ssh keys
func (w *DB) CountUserSSHKeys(u *User) (count uint) {
	w.Model(&Key{}).Where("user_id = ?", u.ID).Count(&count)
	return
}

// UserHints user account hints
func (w *DB) UserHints(q string) (ns []string) {
	ns = make([]string, 0)
	if !WildcardPattern.MatchString(q) {
		return
	}
	q = strings.ToLower(q) + "%"
	us := make([]User, 0)
	w.Select("DISTINCT account").Where("account LIKE ?", q).Find(&us)
	for _, u := range us {
		ns = append(ns, u.Account)
	}
	return
}

// ServerHints server name hints
func (w *DB) ServerHints(q string) (ns []string) {
	ns = make([]string, 0)
	if !WildcardPattern.MatchString(q) {
		return
	}
	q = strings.ToLower(q) + "%"
	us := make([]Server, 0)
	w.Select("DISTINCT name").Where("name LIKE ?", q).Find(&us)
	for _, u := range us {
		ns = append(ns, u.Name)
	}
	return
}

// TargetUserHints target user hints
func (w *DB) TargetUserHints(q string) (ns []string) {
	ns = make([]string, 0)
	if !WildcardPattern.MatchString(q) {
		return
	}
	q = strings.ToLower(q) + "%"
	us := make([]Grant, 0)
	w.Select("DISTINCT target_user").Where("target_user LIKE ?", q).Find(&us)
	for _, u := range us {
		ns = append(ns, u.TargetUser)
	}
	return
}

// CombinedGrant combined grant
type CombinedGrant struct {
	TargetUser string // target user
	ServerName string // server name
	ExpiresAt  *time.Time
}

// GetCombinedGrants get valid combined grants for user
func (w *DB) GetCombinedGrants(uid uint) []CombinedGrant {
	out := []CombinedGrant{}
	ss := []Server{}
	w.Find(&ss)
	gs := []Grant{}
	w.Find(&gs, "user_id = ? AND (expires_at IS NULL OR expires_at > ?)", uid, time.Now())
	for _, g := range gs {
	L2:
		for _, s := range ss {
			if com.MatchAsterisk(g.ServerName, s.Name) {
				for i, o := range out {
					// found same server same user, update expires_at
					if o.ServerName == s.Name &&
						o.TargetUser == g.TargetUser &&
						o.ExpiresAt != nil && (g.ExpiresAt == nil || g.ExpiresAt.After(*o.ExpiresAt)) {
						out[i].ExpiresAt = g.ExpiresAt
						continue L2
					}
				}
				out = append(out, CombinedGrant{
					TargetUser: g.TargetUser,
					ServerName: s.Name,
					ExpiresAt:  g.ExpiresAt,
				})
			}
		}
	}
	return out
}

// UpdateSandboxPublicKeyForAccount update sandbox public key for user with account
func (w *DB) UpdateSandboxPublicKeyForAccount(fp string, account string) (err error) {
	fp = strings.TrimSpace(fp)
	var u = User{}
	if err = w.First(&u, "account = ?", account).Error; err != nil || u.ID == 0 {
		err = fmt.Errorf("user with account %s not found", account)
	}
	var k = Key{}
	if err = w.Attrs(map[string]interface{}{
		"name":        "sandbox",
		"fingerprint": fp,
	}).FirstOrCreate(&k, map[string]interface{}{
		"user_id":    u.ID,
		"is_sandbox": utils.True,
	}).Error; err != nil {
		return
	}
	return
}

// CreateSession create a new session model
func (w *DB) CreateSession(account string) (s *Session, err error) {
	s = &Session{
		UserAccount: account,
		StartedAt:   time.Now(),
	}
	if err = w.Create(s).Error; err != nil {
		return
	}
	if err = w.Model(s).Update(map[string]interface{}{
		"replay_file": s.GenerateReplayFile(),
	}).Error; err != nil {
		return
	}
	return
}
