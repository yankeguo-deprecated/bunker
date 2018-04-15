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
	"strings"

	"github.com/yankeguo/bunker/models"
	"github.com/yankeguo/bunker/utils"
	"golang.org/x/crypto/ssh"
	"magi.systems/net/web"
	"magi.systems/net/web/session"
)

// GetSettingsProfile get profile
func GetSettingsProfile(ctx *web.Context, a Auth) {
	ctx.Data["SideClass_Profile"] = "active"
	ctx.Data["CreatedAt"] = TimeAgo(&a.User().CreatedAt)
	ctx.Data["UsedAt"] = TimeAgo(a.User().UsedAt)
	if utils.ToBool(a.User().IsAdmin) {
		ctx.Data["UserType"] = "管理员"
	} else {
		ctx.Data["UserType"] = "普通用户"
	}
	ctx.HTML(http.StatusOK, "settings/profile")
}

// GetSettingsChangePassword get change password
func GetSettingsChangePassword(ctx *web.Context, a Auth) {
	ctx.Data["SideClass_ChangePassword"] = "active"
	ctx.HTML(http.StatusOK, "settings/change-password")
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

// PostSettingsChangePassword get change password
func PostSettingsChangePassword(ctx *web.Context, f ChangePasswordForm, a Auth, fl *session.Flash, db *models.DB) {
	defer ctx.Redirect("/settings/change-password")
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

// SSHKeyItem ssh key item
type SSHKeyItem struct {
	ID          uint
	Name        string
	Fingerprint string
	UsedAt      string
	CreatedAt   string
	IsSandbox   bool
}

// GetSettingsSSHKeysIndex get keys
func GetSettingsSSHKeysIndex(ctx *web.Context, a Auth, db *models.DB) {
	ctx.Data["SideClass_SSHKeys"] = "active"
	items := []SSHKeyItem{}
	keys := []models.Key{}

	db.Where("user_id = ?", a.User().ID).Find(&keys)

	for _, k := range keys {
		items = append(items, SSHKeyItem{
			ID:          k.ID,
			Name:        k.Name,
			Fingerprint: k.Fingerprint,
			UsedAt:      TimeAgo(k.UsedAt),
			CreatedAt:   TimeAgo(&k.CreatedAt),
			IsSandbox:   utils.ToBool(k.IsSandbox),
		})
	}

	ctx.Data["SSHKeys"] = items

	ctx.HTML(http.StatusOK, "settings/ssh-keys/index")
}

// GetSettingsSSHKeysNew get ssh keys new
func GetSettingsSSHKeysNew(ctx *web.Context, a Auth, db *models.DB) {
	ctx.HTML(http.StatusOK, "settings/ssh-keys/new")
}

// SSHKeyCreateForm add key form
type SSHKeyCreateForm struct {
	Name        string `form:"name"`
	PublicKey   string `form:"public_key"`
	Fingerprint string `form:"-"`
}

// Validate validate the form
func (f SSHKeyCreateForm) Validate(db *models.DB) (SSHKeyCreateForm, error) {
	if len(f.PublicKey) == 0 {
		return f, errors.New("公钥不能为空")
	}
	p, c, _, _, err := ssh.ParseAuthorizedKey([]byte(f.PublicKey))
	if err != nil {
		return f, errors.New("公钥格式错误")
	}
	f.Fingerprint = strings.TrimSpace(ssh.FingerprintSHA256(p))
	if len(f.Name) == 0 {
		f.Name = strings.TrimSpace(c)
	}
	if len(f.Name) == 0 {
		f.Name = "default"
	}
	var count uint
	db.Model(&models.Key{}).Where("fingerprint = ?", f.Fingerprint).Count(&count)
	if count > 0 {
		return f, errors.New("公钥已经被使用")
	}
	return f, nil
}

// PostSettingsSSHKeysCreate add a ssh key
func PostSettingsSSHKeysCreate(ctx *web.Context, a Auth, f SSHKeyCreateForm, fl *session.Flash, db *models.DB) {
	// validate form
	var err error
	if f, err = f.Validate(db); err != nil {
		fl.Error(err.Error())
		ctx.Redirect("/settings/ssh-keys/new")
		return
	}
	// create
	db.Create(&models.Key{
		UserID:      a.User().ID,
		Name:        f.Name,
		Fingerprint: f.Fingerprint,
	})
	ctx.Redirect("/settings/ssh-keys")
}

// PostSettingsSSHKeysDestroy destroy a ssh key
func PostSettingsSSHKeysDestroy(ctx *web.Context, a Auth, db *models.DB) {
	defer ctx.Redirect("/settings/ssh-keys")
	db.Delete(&models.Key{}, "user_id = ? AND id = ? AND is_sandbox = ?", a.User().ID, ctx.Params(":id"), utils.False)
}
