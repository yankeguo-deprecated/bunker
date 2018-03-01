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
	/* home */
	w.Get("/", MustSignedIn(), GetIndex).Name("index")
	w.Get("/login", MustNotSignedIn(), GetLogin).Name("login")
	w.Post("/login", MustNotSignedIn(), csrf.Validate, binding.Form(LoginForm{}), PostLogin)
	w.Post("/logout", MustSignedIn(), csrf.Validate, PostLogout)
	/* settings */
	w.Get("/settings/profile", MustSignedIn(), GetSettingsProfile).Name("profile")
	w.Get("/settings/change-password", MustSignedIn(), GetSettingsChangePassword).Name("change-password")
	w.Post("/settings/change-password", MustSignedIn(), csrf.Validate, binding.Form(ChangePasswordForm{}), PostSettingsChangePassword)
	w.Get("/settings/ssh-keys", MustSignedIn(), GetSettingsSSHKeysIndex).Name("ssh-keys")
	w.Get("/settings/ssh-keys/new", MustSignedIn(), GetSettingsSSHKeysNew).Name("new-ssh-key")
	w.Post("/settings/ssh-keys", MustSignedIn(), csrf.Validate, binding.Form(SSHKeyAddForm{}), PostSettingsSSHKeysCreate)
	w.Post("/settings/ssh-keys/:id/destroy", MustSignedIn(), csrf.Validate, PostSettingsSSHKeysDestroy).Name("destroy-ssh-key")
	/* servers */
	w.Get("/servers", MustSignedInAsAdmin(), GetServersIndex).Name("servers")
	w.Get("/servers/new", MustSignedInAsAdmin(), GetServersNew).Name("new-server")
	w.Get("/servers/master-key", MustSignedInAsAdmin(), GetMasterKey).Name("master-key")
	w.Post("/servers", MustSignedInAsAdmin(), csrf.Validate, binding.Form(ServerCreateForm{}), PostServerCreate)
	w.Get("/servers/:id/edit", MustSignedInAsAdmin(), GetServerEdit).Name("edit-server")
	w.Post("/servers/:id/update", MustSignedInAsAdmin(), csrf.Validate, binding.Form(ServerCreateForm{}), PostServerUpdate).Name("update-server")
	w.Post("/servers/:id/destroy", MustSignedInAsAdmin(), csrf.Validate, PostServerDestroy).Name("destroy-server")
	/* users */
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
