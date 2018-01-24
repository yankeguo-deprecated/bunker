/**
 * models/user.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"ireul.com/orm"
)

// User user model
type User struct {
	orm.Model
	Login          string     `orm:"unique_index" json:"login"` // login name
	Nickname       string     `json:"nickname"`                 // nickname of user
	PasswordDigest string     `orm:"type:text" json:"-"`        // digest of password
	IsAdmin        bool       `orm:"not null" json:"isAdmin"`   // is this user system admin
	IsBlocked      bool       `orm:"not null" json:"isBlocked"` // is this user blocked
	UsedAt         *time.Time `json:"usedAt"`                   // last seen at
}

// SetPassword update password for user
func (u *User) SetPassword(p string) (err error) {
	var b []byte
	if b, err = bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost); err != nil {
		return
	}
	u.PasswordDigest = string(b)
	return
}

// CheckPassword check password
func (u *User) CheckPassword(p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordDigest), []byte(p)) == nil
}
