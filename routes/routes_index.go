/**
 * routes/routes_home.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import "ireul.com/web"

func index(ctx *web.Context, r web.Render) {
	ctx.HTML(200, "index")
}

func login(ctx *web.Context, r web.Render) {
	ctx.HTML(200, "login")
}
