/**
 * routes/routes_users.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"
	"strings"

	"ireul.com/bunker/models"
	"ireul.com/web"
	"ireul.com/web/session"
)

// UserItem user item
type UserItem struct {
	ID        uint
	Account   string
	CreatedAt string
	Type      string
	UsedAt    string
	IsAdmin   bool
	IsBlocked bool
	IsCurrent bool
}

// GetUsers show users
func GetUsers(ctx *web.Context, db *models.DB, a Auth) {
	ctx.Data["NamePattern"] = models.NamePattern.String()
	ctx.Data["NavClass_Users"] = "active"

	items := []UserItem{}
	users := []models.User{}
	db.Order("is_blocked").Order("is_admin DESC").Find(&users)

	for _, u := range users {
		tags := []string{}
		if u.IsAdmin {
			tags = append(tags, "管理员")
		} else {
			tags = append(tags, "普通用户")
		}
		if u.IsBlocked {
			tags = append(tags, "已封禁")
		}
		items = append(items, UserItem{
			ID:        u.ID,
			Account:   u.Account,
			Type:      strings.Join(tags, ","),
			CreatedAt: TimeAgo(&u.CreatedAt),
			UsedAt:    TimeAgo(u.UsedAt),
			IsAdmin:   u.IsAdmin,
			IsBlocked: u.IsBlocked,
			IsCurrent: u.ID == a.User().ID,
		})
	}
	ctx.Data["Users"] = items

	ctx.HTML(200, "users")
}

// UserAddForm user add form
type UserAddForm struct {
	Account  string `form:"account"`
	Password string `form:"password"`
}

// Validate validate the form
func (f UserAddForm) Validate(db *models.DB) (UserAddForm, error) {
	if !models.NamePattern.MatchString(f.Account) {
		return f, errors.New("用户名不符合规则")
	}
	if len(f.Password) < 6 {
		return f, errors.New("密码过短")
	}
	var c uint
	db.Model(&models.User{}).Where("account = ?", f.Account).Count(&c)
	if c > 0 {
		return f, errors.New("用户名已经被占用")
	}
	return f, nil
}

// PostUserAdd post user add
func PostUserAdd(ctx *web.Context, f UserAddForm, db *models.DB, fl *session.Flash) {
	defer ctx.Redirect("/users")
	var err error
	if f, err = f.Validate(db); err != nil {
		fl.Error(err.Error())
		return
	}
	u := &models.User{
		Account: f.Account,
	}
	u.SetPassword(f.Password)
	db.Create(u)
}

// UserUpdateForm user update form
type UserUpdateForm struct {
	ID        string `form:"id"`
	IsAdmin   string `form:"is_admin"`
	IsBlocked string `form:"is_blocked"`
}

// PostUserUpdate post user update
func PostUserUpdate(ctx *web.Context, f UserUpdateForm, db *models.DB) {
	defer ctx.Redirect("/users")

	attrs := map[string]interface{}{}

	if len(f.IsAdmin) > 0 {
		attrs["is_admin"] = strings.ToLower(f.IsAdmin) == "y"
	}
	if len(f.IsBlocked) > 0 {
		attrs["is_blocked"] = strings.ToLower(f.IsBlocked) == "y"
	}

	u := models.User{}
	db.Find(&u, f.ID)
	db.Model(&u).Update(attrs)
}
