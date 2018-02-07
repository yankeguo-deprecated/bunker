/**
 * routes/routes_profile.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"net/http"

	"ireul.com/web"
)

// GetProfile get change password
func GetProfile(ctx *web.Context) {
	ctx.HTML(http.StatusOK, "profile")
}

// ChangeNicknameForm change nickname form
type ChangeNicknameForm struct {
}

// PostChangeNickname change nickname form
func PostChangeNickname() {
}

// ChangePasswordForm change password form
type ChangePasswordForm struct {
}

// PostChangePassword get change password
func PostChangePassword() {
}
