/**
 * routes/routes_users.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import "ireul.com/web"

// GetUsers show users
func GetUsers(ctx *web.Context) {
	ctx.Data["NavClass_Users"] = "active"
	ctx.HTML(200, "users")
}

// UserAddForm user add form
type UserAddForm struct {
}

// PostUserAdd post user add
func PostUserAdd(ctx *web.Context, f UserAddForm) {
}
