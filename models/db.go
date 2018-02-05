/**
 * models/db.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"fmt"
	"regexp"
	"time"

	"ireul.com/bunker/types"
	"ireul.com/orm"
)

// NamePattern general name pattern
var NamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\._-]{3,15}$`)

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
	if d, err = orm.Open("mysql", cfg.DB.URL); err != nil {
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
		Group{},
		User{},
		Key{},
		Grant{},
	).Error
}

// Touch update the UsedAt field
func (w *DB) Touch(ms ...interface{}) {
	for _, m := range ms {
		w.Model(m).UpdateColumn("UsedAt", time.Now())
	}
}

// EnsureGroup ensure a server group
func (w *DB) EnsureGroup(name string) (g *Group, err error) {
	g = &Group{}
	err = w.FirstOrCreate(g, map[string]interface{}{"name": name}).Error
	return
}

// CheckGrant check target grant
func (w *DB) CheckGrant(user User, srv Server, targetUser string) (err error) {
	n := time.Now()
	g := Grant{}
	// check user -> server grants
	w.Where("user_id = ? AND target_type = ? AND target_id = ? AND target_user = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, GrantTargetServer, srv.ID, targetUser, n).First(&g)
	if g.ID != 0 {
		return nil
	}
	// check user -> server group grants
	w.Where("user_id = ? AND target_type = ? AND target_id = ? AND target_user = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, GrantTargetGroup, srv.GroupID, targetUser, n).First(&g)
	if g.ID != 0 {
		return nil
	}
	return fmt.Errorf("Grant not find")
}
