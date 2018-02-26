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
	"ireul.com/bunker/models"
	"ireul.com/web"
)

// GetGrants get all grants
func GetGrants() {
}

// GrantAddForm grant add form
type GrantAddForm struct {
	UserID     string `form:"user_id"`
	TargetType string `form:"target_type"`
	TargetName string `form:"target_name"`
	TargetUser string `form:"target_user"`
	ExpiresAt  string `form:"expires_at"`
}

// PostGrantAdd create or update a grant
func PostGrantAdd(ctx *web.Context, f GrantAddForm) {
	defer ctx.Redirect("/grants")
}

// GrantDestroyForm grant destroy form
type GrantDestroyForm struct {
	ID string `form:"id"`
}

// PostGrantDestroy destroy a grant
func PostGrantDestroy(ctx *web.Context, db *models.DB, f GrantDestroyForm) {
	defer ctx.Redirect("/grants")
	db.Delete(&models.Grant{}, f.ID)
}
