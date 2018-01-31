/**
 * models/db.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"time"

	"ireul.com/bunker/types"
	"ireul.com/orm"
)

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
		ServerGroup{},
		ServerGroupRef{},
		User{},
		UserGroup{},
		UserGroupRef{},
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

// CheckGrant check target grant
func (w *DB) CheckGrant(user User, srv Server, targetUser string) (err error) {
	return nil
}
