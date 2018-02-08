/**
 * routes/routes_profile.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"net/http"

	"ireul.com/bunker/models"
	"ireul.com/web"
	"ireul.com/web/session"
)

// GetProfile get change password
func GetProfile(ctx *web.Context, a Auth) {
	ctx.Data["CreatedAt"] = TimeAgo(&a.User().CreatedAt)
	ctx.Data["UsedAt"] = TimeAgo(a.User().UsedAt)
	ctx.HTML(http.StatusOK, "profile")
}

// ChangePasswordForm change password form
type ChangePasswordForm struct {
	OldPassword string `form:"old_password"`
	NewPassword string `form:"new_password"`
	RptPassword string `form:"rpt_password"`
}

// PostChangePassword get change password
func PostChangePassword(ctx *web.Context, f ChangePasswordForm, a Auth, fl *session.Flash, db *models.DB) {
	defer ctx.Redirect("/profile")
	if f.NewPassword != f.RptPassword {
		fl.Error("重复密码不正确")
	}
	if len(f.NewPassword) < 6 {
		fl.Error("新密码长度不足")
		return
	}
	if !a.User().CheckPassword(f.OldPassword) {
		fl.Error("旧密码不正确")
		return
	}
	fl.Success("密码修改成功")
	u := a.User()
	u.SetPassword(f.NewPassword)
	db.Model(u).Update("password_digest", u.PasswordDigest)
}
