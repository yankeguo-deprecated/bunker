/**
 * models/user.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User user model
type User struct {
	Model
	Account        string     `orm:"not null;unique_index" json:"account"`      // account name
	PasswordDigest string     `orm:"not null;type:text" json:"-"`               // digest of password
	IsAdmin        bool       `orm:"not null;default:'false'" json:"isAdmin"`   // is this user system admin
	IsBlocked      bool       `orm:"not null;default:'false'" json:"isBlocked"` // is this user blocked
	UsedAt         *time.Time `orm:"" json:"usedAt"`                            // last seen at
}

// BeforeSave before save callback
func (u *User) BeforeSave() (err error) {
	if !NamePattern.MatchString(u.Account) {
		err = errors.New(`invalid field user.account, allows 3~15 letters, numbers, "_" or "-"`)
	}
	return
}

// SetPassword update password for user
// bcrypt produces clear text encrypted password, no further encoding needed
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
