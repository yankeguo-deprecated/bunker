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
	"net/url"
	"regexp"
	"strings"
	"time"

	"ireul.com/bunker/types"
	"ireul.com/mysql" // mysql adapter
	"ireul.com/orm"
)

// NamePattern general name pattern
var NamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\._-]{3,}$`)

// HintPattern general name hint pattern
var HintPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\._-]*$`)

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
	var u *url.URL
	if u, err = url.Parse(cfg.DB.URL); err != nil {
		return
	}
	if u.Scheme != "mysql" {
		err = errors.New("only mysql:// is supported")
		return
	}

	// rebuild DSN from mysql:// url
	c := mysql.NewConfig()
	c.User = u.User.Username()
	c.Passwd, _ = u.User.Password()
	c.Net = "tcp"
	c.Loc = time.Local
	c.Addr = u.Host
	c.DBName = u.Path
	if strings.HasPrefix(c.DBName, "/") {
		c.DBName = c.DBName[1:]
	}
	c.ParseTime = true

	var d *orm.DB
	if d, err = orm.Open("mysql", c.FormatDSN()); err != nil {
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
func (w *DB) CheckGrant(user User, srv Server, targetUser string) (err error) {
	g := Grant{}
	w.Where("user_id = ? AND target_user = ? AND ((target_name = ? AND target_type = ?) OR (target_name = ? AND target_type = ?)) AND (expires_at IS NULL OR expires_at > ?)",
		user.ID,
		targetUser,
		srv.Name,
		GrantTargetServer,
		srv.GroupName,
		GrantTargetGroup,
		time.Now(),
	).First(&g)
	if g.ID != 0 {
		return nil
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
	if !HintPattern.MatchString(q) {
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
	if !HintPattern.MatchString(q) {
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

// GroupHints group name hints
func (w *DB) GroupHints(q string) (ns []string) {
	ns = make([]string, 0)
	if !HintPattern.MatchString(q) {
		return
	}
	q = strings.ToLower(q) + "%"
	us := make([]Server, 0)
	w.Select("DISTINCT group_name").Where("group_name LIKE ?", q).Find(&us)
	for _, u := range us {
		ns = append(ns, u.GroupName)
	}
	return
}

// TargetUserHints target user hints
func (w *DB) TargetUserHints(q string) (ns []string) {
	ns = make([]string, 0)
	if !HintPattern.MatchString(q) {
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
	User      string // target user
	Name      string // server name
	GroupName string // group name
	ExpiresAt *time.Time
}

// GetCombinedGrants get valid combined grants for user
func (w *DB) GetCombinedGrants(uid uint) []CombinedGrant {
	cs := []CombinedGrant{}
	n := time.Now()
	w.Raw(
		`SELECT G.target_user AS user, S.name AS name, S.group_name AS group_name, G.expires_at AS expires_at FROM grants AS G JOIN servers AS S ON (S.group_name = G.target_name AND G.target_type = ?) OR (S.name = G.target_name AND G.target_type = ?) WHERE G.user_id = ? AND (G.expires_at IS NULL OR G.expires_at > ?)`,
		GrantTargetGroup,
		GrantTargetServer,
		uid,
		n,
	).Scan(&cs)
	out := []CombinedGrant{}
L1:
	for _, ic := range cs {
		for i, oc := range out {
			if ic.User == oc.User && ic.Name == oc.Name {
				if ic.ExpiresAt == nil || (oc.ExpiresAt != nil && ic.ExpiresAt.After(*oc.ExpiresAt)) {
					out[i].ExpiresAt = ic.ExpiresAt
				}
				continue L1
			}
		}
		out = append(out, ic)
	}
	return out
}
