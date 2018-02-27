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
	w.Get("/settings/profile", MustSignedIn(), GetProfile)
	w.Get("/settings/change-password", MustSignedIn(), GetChangePassword)
	w.Post("/settings/change-password", MustSignedIn(), csrf.Validate, binding.Form(ChangePasswordForm{}), PostChangePassword)
	w.Get("/settings/ssh-keys", MustSignedIn(), GetSSHKeys)
	w.Get("/settings/ssh-keys/new", MustSignedIn(), GetSSHKeysNew)
	w.Post("/settings/ssh-keys", MustSignedIn(), csrf.Validate, binding.Form(SSHKeyAddForm{}), PostSSHKeyAdd)
	w.Post("/settings/ssh-keys/destroy", MustSignedIn(), csrf.Validate, binding.Form(SSHKeyDestroyForm{}), PostSSHKeyDestroy)
	w.Get("/servers", MustSignedInAsAdmin(), GetServers)
	w.Post("/servers/add", MustSignedInAsAdmin(), csrf.Validate, binding.Form(ServerAddForm{}), PostServerAdd)
	w.Post("/servers/destroy", MustSignedInAsAdmin(), csrf.Validate, binding.Form(ServerDestroyForm{}), PostServerDestroy)
	w.Get("/users", MustSignedInAsAdmin(), GetUsers)
	w.Post("/users/add", MustSignedInAsAdmin(), csrf.Validate, binding.Form(UserAddForm{}), PostUserAdd)
	w.Post("/users/update", MustSignedInAsAdmin(), csrf.Validate, binding.Form(UserUpdateForm{}), PostUserUpdate)
	w.Get("/grants", MustSignedInAsAdmin(), GetGrants)
	w.Post("/grants/add", MustSignedInAsAdmin(), csrf.Validate, binding.Form(GrantAddForm{}), PostGrantAdd)
	w.Post("/grants/destroy", MustSignedInAsAdmin(), csrf.Validate, binding.Form(GrantDestroyForm{}), PostGrantDestroy)
	w.Get("/api/hints/users", MustSignedInAsAdmin(), GetUserHints)
	w.Get("/api/hints/servers", MustSignedInAsAdmin(), GetServerHints)
	w.Get("/api/hints/groups", MustSignedInAsAdmin(), GetGroupHints)
	w.Get("/api/hints/target-users", MustSignedInAsAdmin(), GetTargetUserHints)
}

// GeneralFilter the general filter
func GeneralFilter(ctx *web.Context, cfg types.Config) {
	ctx.Data["Config"] = cfg
	ctx.Next()
}
