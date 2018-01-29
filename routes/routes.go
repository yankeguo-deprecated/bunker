/**
 * routes/routes.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"ireul.com/web"
)

// Mount mount all routes
func Mount(w *web.Web) {
	w.Get("/ping", func(ctx *web.Context) {
		ctx.PlainText(200, []byte("Pong"))
	})
}
