/**
 * routes_hint.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"github.com/yankeguo/bunker/models"
	"landzero.net/x/net/web"
)

// GetUserHints get user hints
func GetUserHints(ctx *web.Context, db *models.DB) {
	ns := db.UserHints(ctx.Query("q"))
	ctx.JSON(200, map[string]interface{}{"hints": ns})
}

// GetServerHints get server hints
func GetServerHints(ctx *web.Context, db *models.DB) {
	ns := db.ServerHints(ctx.Query("q"))
	ctx.JSON(200, map[string]interface{}{"hints": ns})
}

// GetTargetUserHints get target user hints
func GetTargetUserHints(ctx *web.Context, db *models.DB) {
	ns := db.TargetUserHints(ctx.Query("q"))
	ctx.JSON(200, map[string]interface{}{"hints": ns})
}
