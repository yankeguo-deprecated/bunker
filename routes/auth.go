/**
 * routes/auth.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"fmt"
	"net/http"

	"ireul.com/bunker/models"
	"ireul.com/web"
	"ireul.com/web/session"
)

// Auth auth result
type Auth interface {
	User() *models.User
	SetUser(u *models.User)
	SignedIn() bool
	SignedInAsAdmin() bool
}

type auth struct {
	fetched bool         // already fetched
	user    *models.User // user
	db      *models.DB
	sess    session.Store // session
}

func (a *auth) SignedIn() bool {
	return a.User() != nil
}

func (a *auth) SignedInAsAdmin() bool {
	return a.User() != nil && a.User().IsAdmin
}

func (a *auth) User() *models.User {
	if a.fetched {
		return a.user
	}
	if userID, ok := a.sess.Get("user_id").(string); ok && len(userID) > 0 {
		u := models.User{}
		if err := a.db.First(&u, userID).Error; err == nil && u.ID != 0 {
			a.user = &u
		} else {
			// clear user_id if failed to find
			a.SetUser(nil)
		}
	}
	a.fetched = true
	return a.user
}

func (a *auth) SetUser(u *models.User) {
	a.fetched = true
	a.user = u
	if u == nil {
		a.sess.Delete("user_id")
	} else {
		a.sess.Set("user_id", fmt.Sprintf("%d", u.ID))
	}
}

// Authenticator inject Auth to web.Context
func Authenticator() web.Handler {
	return func(ctx *web.Context, sess session.Store, db *models.DB) {
		a := &auth{sess: sess, db: db}
		// inject
		ctx.Data["Auth"] = a
		ctx.MapTo(a, (*Auth)(nil))
		ctx.Next()
	}
}

// MustNotSignedIn requires not signed in
func MustNotSignedIn() web.Handler {
	return func(a Auth, ctx *web.Context) {
		if a.SignedIn() {
			ctx.Redirect("/", http.StatusTemporaryRedirect)
		} else {
			ctx.Next()
		}
	}
}

// MustSignedIn requires signed in
func MustSignedIn() web.Handler {
	return func(a Auth, ctx *web.Context) {
		if !a.SignedIn() {
			ctx.Redirect("/login", http.StatusTemporaryRedirect)
		} else {
			ctx.Next()
		}
	}
}

// MustSignedInAsAdmin requires signed in as admin
func MustSignedInAsAdmin() web.Handler {
	return func(a Auth, ctx *web.Context) {
		if !a.SignedInAsAdmin() {
			if a.SignedIn() {
				ctx.Redirect("/", http.StatusTemporaryRedirect)
			} else {
				ctx.Redirect("/login", http.StatusTemporaryRedirect)
			}
		} else {
			ctx.Next()
		}
	}
}
