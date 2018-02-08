/**
 * routes/routes_keys.go
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

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
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
		items = append(items, SSHKeyItem{
			ID:          k.ID,
			Name:        k.Name,
			Fingerprint: k.Fingerprint,
			UsedAt:      TimeAgo(k.UsedAt),
			CreatedAt:   TimeAgo(&k.CreatedAt),
		})
	}

	ctx.Data["SSHKeys"] = items

	ctx.HTML(http.StatusOK, "ssh-keys")
}

// SSHKeyAddForm add key form
type SSHKeyAddForm struct {
	Name        string `form:"name"`
	PublicKey   string `form:"public_key"`
	Fingerprint string `form:"-"`
}

// Validate validate the form
func (f SSHKeyAddForm) Validate(db *models.DB) (SSHKeyAddForm, error) {
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

// PostSSHKeyAdd add a ssh key
func PostSSHKeyAdd(ctx *web.Context, a Auth, f SSHKeyAddForm, fl *session.Flash, db *models.DB) {
	defer ctx.Redirect("/ssh-keys")
	// validate form
	var err error
	if f, err = f.Validate(db); err != nil {
		fl.Error(err.Error())
		return
	}
	// create
	db.Create(&models.Key{
		UserID:      a.User().ID,
		Name:        f.Name,
		Fingerprint: f.Fingerprint,
	})
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
