/**
 * routes/routes_keys.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/timeago"
	"ireul.com/web"
	"ireul.com/web/binding"
	"ireul.com/web/session"
)

// SSHKeyItem ssh key item
type SSHKeyItem struct {
	ID          uint
	Name        string
	Fingerprint string
	UsedAt      string
	CreatedAt   string
}

// GetSSHKeys get keys
func GetSSHKeys(ctx *web.Context, a Auth, db *models.DB) {
	items := []SSHKeyItem{}
	keys := []models.Key{}

	db.Where("user_id = ?", a.User().ID).Find(&keys)

	for _, k := range keys {
		at := "从未使用"
		if k.UsedAt != nil {
			at = timeago.Chinese.Format(*k.UsedAt)
		}
		items = append(items, SSHKeyItem{
			ID:          k.ID,
			Name:        k.Name,
			Fingerprint: k.Fingerprint,
			UsedAt:      at,
			CreatedAt:   timeago.Chinese.Format(k.CreatedAt),
		})
	}

	ctx.Data["SSHKeys"] = items

	ctx.HTML(http.StatusOK, "ssh-keys")
}

// SSHKeyAddForm add key form
type SSHKeyAddForm struct {
	Name      string `form:"name"`
	PublicKey string `form:"public_key" binding:"Required"`
}

// PostSSHKeyAdd add a ssh key
func PostSSHKeyAdd(ctx *web.Context, a Auth, f SSHKeyAddForm, ferrs binding.Errors, fl *session.Flash, db *models.DB) {
	defer ctx.Redirect("/ssh-keys")
	if ferrs.Len() > 0 {
		fl.Error("公钥不能为空")
		return
	}
	var p ssh.PublicKey
	var err error
	var c string
	if p, c, _, _, err = ssh.ParseAuthorizedKey([]byte(f.PublicKey)); err != nil {
		fl.Error("公钥格式错误")
		return
	}
	if len(f.Name) == 0 {
		f.Name = strings.TrimSpace(c)
	}
	if len(f.Name) == 0 {
		f.Name = "未命名"
	}
	fp := strings.TrimSpace(ssh.FingerprintSHA256(p))
	var count uint
	db.Model(&models.Key{}).Where("fingerprint = ?", fp).Count(&count)
	if count > 0 {
		fl.Error("公钥已经被使用")
		return
	}
	k := models.Key{
		UserID:      a.User().ID,
		Name:        f.Name,
		Fingerprint: fp,
	}
	db.Create(&k)
}

// SSHKeyDestroyForm destroy a ssh key
type SSHKeyDestroyForm struct {
	KeyID string `form:"key_id" binding:"Required"`
}

// PostSSHKeyDestroy destroy a ssh key
func PostSSHKeyDestroy(ctx *web.Context, a Auth, f SSHKeyDestroyForm, ferrs binding.Errors, db *models.DB) {
	defer ctx.Redirect("/ssh-keys")
	db.Delete(&models.Key{}, "user_id = ? AND id = ?", a.User().ID, f.KeyID)
}
