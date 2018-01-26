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
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
	"ireul.com/orm"
)

// UserLoginPattern 用户登录名正则表达式
var UserLoginPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{3,15}$`)

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

// BeforeSave before save callback
func (u *User) BeforeSave() (err error) {
	if len(u.Nickname) == 0 {
		u.Nickname = u.Login
	}
	if !UserLoginPattern.MatchString(u.Login) {
		err = errors.New(`invalid field user.login, allows 3~15 letters, numbers, "_" or "-"`)
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
