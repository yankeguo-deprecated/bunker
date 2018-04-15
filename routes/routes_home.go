/**
 * routes/routes_index.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"
	"fmt"

	"github.com/yankeguo/bunker/models"
	"github.com/yankeguo/bunker/types"
	"magi.systems/net/web"
	"magi.systems/net/web/captcha"
	"magi.systems/net/web/session"
)

// CombinedGrantItem combined grant
type CombinedGrantItem struct {
	TargetUser string // target user
	ServerName string // server name
	ExpiresAt  string // expires at
}

// GetIndex get index page
func GetIndex(ctx *web.Context, r web.Render, a Auth, db *models.DB, cfg types.Config) {
	ctx.Data["NavClass_Index"] = "active"
	ctx.Data["MissingSSHKeys"] = db.CountUserSSHKeys(a.User()) == 0
	if cfg.SSHD.Port != 22 {
		ctx.Data["SSHCommandSuffix"] = fmt.Sprintf(" -p %d", cfg.SSHD.Port)
	} else {
		ctx.Data["SSHCommandSuffix"] = ""
	}

	ci := []CombinedGrantItem{}
	cs := db.GetCombinedGrants(a.User().ID)

	for _, c := range cs {
		ci = append(ci, CombinedGrantItem{
			ServerName: c.ServerName,
			TargetUser: c.TargetUser,
			ExpiresAt:  TimeAgo(c.ExpiresAt),
		})
	}

	ctx.Data["CombinedGrants"] = ci
	ctx.HTML(200, "index")
}

// GetLogin get login page
func GetLogin(ctx *web.Context) {
	ctx.HTML(200, "login")
}

// LoginForm the login form
type LoginForm struct {
	Account  string `form:"account"`
	Password string `form:"password"`
}

// Validate validate form
func (f LoginForm) Validate(db *models.DB) (u *models.User, err error) {
	if len(f.Account) == 0 {
		err = errors.New("请输入用户名")
		return
	}
	if len(f.Password) == 0 {
		err = errors.New("请输入密码")
		return
	}
	if u, err = db.FindUserByLogin(f.Account, f.Password); err != nil {
		err = errors.New("请填写正确的用户名和密码")
		return
	}
	return
}

// PostLogin get login page
func PostLogin(ctx *web.Context, f LoginForm, fl *session.Flash, a Auth, db *models.DB, cap *captcha.Captcha, sess session.Store) {
	var err error
	var u *models.User

	if !cap.VerifyReq(ctx.Req) {
		err = errors.New("请填写正确的验证码")
	} else {
		u, err = f.Validate(db)
	}

	if err != nil {
		fl.Error(err.Error())
		ctx.Redirect("/login")
		return
	}

	db.Touch(u)
	a.SetUser(u)
	ctx.Redirect("/")
}

// PostLogout logout
func PostLogout(ctx *web.Context, a Auth) {
	a.SetUser(nil)
	ctx.Redirect("/login")
}
