/**
 * routes/routes.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/web"
	"ireul.com/web/session"
)

// Mount mount all routes
func Mount(w *web.Web) {
	w.Use(GeneralFilter)
	w.Use(Authenticator())
	w.Get("/", MustSignedIn(), index)
	w.Get("/login", MustNotSignedIn(), login)
	w.Post("/login", MustNotSignedIn(), login)
}

// GeneralFilter the general filter
func GeneralFilter(ctx *web.Context, cfg types.Config, sess session.Store, db *models.DB) {
	ctx.Data["Config"] = cfg
}
