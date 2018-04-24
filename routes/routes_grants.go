/**
 * routes_grant.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yankeguo/bunker/models"
	"islandzero.net/x/database/orm"
	"islandzero.net/x/net/web"
	"islandzero.net/x/net/web/session"
)

// GrantItem grant item
type GrantItem struct {
	ID         uint
	ServerName string
	TargetUser string
	ExpiresAt  string
	IsExpired  bool
	UpdatedAt  string
}

// GetGrantsIndex get grants index
func GetGrantsIndex(ctx *web.Context, db *models.DB, fl *session.Flash) {
	var err error
	u := models.User{}
	if err = db.First(&u, ctx.Params(":userid")).Error; err != nil {
		fl.Error(fmt.Sprintf("无法找到用户"))
		ctx.Redirect(ctx.URLFor("users"))
		return
	}
	ctx.Data["User"] = u
	gs := []models.Grant{}
	db.Where("user_id = ?", u.ID).Find(&gs)
	ti := make([]GrantItem, 0)
	n := time.Now()
	for _, g := range gs {
		ti = append(ti, GrantItem{
			ID:         g.ID,
			ServerName: g.ServerName,
			TargetUser: g.TargetUser,
			ExpiresAt:  TimeAgo(g.ExpiresAt),
			IsExpired:  (g.ExpiresAt != nil && n.After(*g.ExpiresAt)),
			UpdatedAt:  TimeAgo(&g.UpdatedAt),
		})
	}
	ctx.Data["Grants"] = ti
	ctx.HTML(200, "grants/index")
}

// GrantCreateForm grant add form
type GrantCreateForm struct {
	TargetUser  string `form:"target_user"`
	ServerName  string `form:"server_name"`
	ExpiresIn   string `form:"expires_in"`
	ExpiresUnit string `form:"expires_unit"`
}

// Validate validate
func (f GrantCreateForm) Validate() (GrantCreateForm, error) {
	f.TargetUser = strings.TrimSpace(f.TargetUser)
	f.ServerName = strings.TrimSpace(f.ServerName)
	switch f.ExpiresUnit {
	case "h", "d", "e":
		break
	default:
		return f, errors.New("参数错误 expires_unit")
	}
	if !models.WildcardPattern.MatchString(f.ServerName) {
		return f, errors.New("服务器名称不符合规则")
	}
	if !models.NamePattern.MatchString(f.TargetUser) {
		return f, errors.New("账户名称不符合规则")
	}
	if ei, err := strconv.Atoi(f.ExpiresIn); err != nil || ei < 0 {
		return f, errors.New("输入的时间无效")
	}
	return f, nil
}

// PostGrantsCreate create or update a grant
func PostGrantsCreate(ctx *web.Context, f GrantCreateForm, fl *session.Flash, db *models.DB, a Auth) {
	userID := ctx.Params(":userid")
	defer ctx.Redirect(ctx.URLFor("user-grants", ":userid", userID))

	var err error
	if f, err = f.Validate(); err != nil {
		fl.Error(err.Error())
		return
	}

	g := models.Grant{}

	am := map[string]interface{}{}

	if f.ExpiresUnit == "e" {
		am["expires_at"] = orm.Expr("NULL")
	} else {
		eu := time.Hour
		if f.ExpiresUnit == "d" {
			eu = eu * 24
		}
		ei, _ := strconv.Atoi(f.ExpiresIn)
		am["expires_at"] = time.Now().Add(eu * time.Duration(ei))
	}

	_userID, _ := strconv.Atoi(userID)

	if err = db.Where(map[string]interface{}{
		"user_id":     _userID,
		"server_name": f.ServerName,
		"target_user": f.TargetUser,
	}).Assign(am).FirstOrCreate(&g).Error; err != nil {
		fl.Error(err.Error())
	}
}

// PostGrantDestroy destroy a grant
func PostGrantDestroy(ctx *web.Context, db *models.DB) {
	userID := ctx.Params(":userid")
	defer ctx.Redirect(ctx.URLFor("user-grants", ":userid", userID))
	db.Delete(&models.Grant{}, "user_id = ? AND id = ?", userID, ctx.Params(":id"))
}
