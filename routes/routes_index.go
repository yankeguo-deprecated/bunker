/**
 * routes/routes_index.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"ireul.com/bunker/models"
	"ireul.com/web"
)

// GrantItem a grant item
type GrantItem struct {
	ServerName string         // server name
	SubItems   []GrantSubItem // sub items
}

// GrantSubItem a grant subitem
type GrantSubItem struct {
	ServerName string
	TargetUser string
	ExpiresAt  string
}

// GetIndex get index page
func GetIndex(ctx *web.Context, r web.Render, a Auth, db *models.DB) {
	ctx.Data["MissingSSHKeys"] = db.CountUserSSHKeys(a.User()) == 0
	ctx.HTML(200, "index")
}
