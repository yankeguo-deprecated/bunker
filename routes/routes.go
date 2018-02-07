/**
 * routes/routes.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"ireul.com/bunker/types"
	"ireul.com/web"
	"ireul.com/web/binding"
	"ireul.com/web/csrf"
)

// Mount mount all routes
func Mount(w *web.Web) {
	w.Use(GeneralFilter)
	w.Use(Authenticator())
	w.Get("/", MustSignedIn(), GetIndex)
	w.Get("/login", MustNotSignedIn(), GetLogin)
	w.Post("/login", MustNotSignedIn(), csrf.Validate, binding.Form(LoginForm{}), PostLogin)
	w.Post("/logout", MustSignedIn(), csrf.Validate, PostLogout)
}

// GeneralFilter the general filter
func GeneralFilter(ctx *web.Context, cfg types.Config) {
	ctx.Data["Config"] = cfg
}
