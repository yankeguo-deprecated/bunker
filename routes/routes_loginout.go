/**
 * routes/routes_home.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"

	"ireul.com/bunker/models"
	"ireul.com/web"
	"ireul.com/web/binding"
	"ireul.com/web/captcha"
	"ireul.com/web/session"
)

// GetLogin get login page
func GetLogin(ctx *web.Context) {
	ctx.HTML(200, "login")
}

// LoginForm the login form
type LoginForm struct {
	Account  string `form:"account" binding:"Required"`
	Password string `form:"password" binding:"Required"`
}

// PostLogin get login page
func PostLogin(ctx *web.Context, f LoginForm, ferrs binding.Errors, fl *session.Flash, a Auth, db *models.DB, cap *captcha.Captcha) {
	var err error
	var u *models.User

	switch {
	case !cap.VerifyReq(ctx.Req):
		err = errors.New("请填写正确的验证码")
		break
	case ferrs.Len() > 0:
		err = errors.New("请填写正确的用户名和密码")
		break
	default:
		if u, err = db.FindUserByLogin(f.Account, f.Password); err != nil {
			err = errors.New("请填写正确的用户名和密码")
		}
	}

	if err != nil {
		fl.Error(err.Error(), true)
		ctx.HTML(200, "login")
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
