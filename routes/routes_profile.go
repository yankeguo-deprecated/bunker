/**
 * routes/routes_profile.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"
	"net/http"

	"ireul.com/bunker/models"
	"ireul.com/web"
	"ireul.com/web/session"
)

// GetProfile get change password
func GetProfile(ctx *web.Context, a Auth) {
	ctx.Data["NavClass_Profile"] = "active"
	ctx.Data["CreatedAt"] = TimeAgo(&a.User().CreatedAt)
	ctx.Data["UsedAt"] = TimeAgo(a.User().UsedAt)
	if a.User().IsAdmin {
		ctx.Data["UserType"] = "管理员"
	} else {
		ctx.Data["UserType"] = "普通用户"
	}
	ctx.HTML(http.StatusOK, "profile")
}

// ChangePasswordForm change password form
type ChangePasswordForm struct {
	OldPassword string `form:"old_password"`
	NewPassword string `form:"new_password"`
	RptPassword string `form:"rpt_password"`
}

// Validate validate form
func (f ChangePasswordForm) Validate(a Auth) (ChangePasswordForm, error) {
	if f.NewPassword != f.RptPassword {
		return f, errors.New("重复密码不正确")
	}
	if len(f.NewPassword) < 6 {
		return f, errors.New("新密码长度不足")
	}
	if !a.User().CheckPassword(f.OldPassword) {
		return f, errors.New("旧密码不正确")
	}
	return f, nil
}

// PostChangePassword get change password
func PostChangePassword(ctx *web.Context, f ChangePasswordForm, a Auth, fl *session.Flash, db *models.DB) {
	defer ctx.Redirect("/profile")
	var err error
	if f, err = f.Validate(a); err != nil {
		fl.Error(err.Error())
		return
	}
	u := a.User()
	u.SetPassword(f.NewPassword)
	db.Model(u).Update("password_digest", u.PasswordDigest)
	fl.Success("密码修改成功")
}
