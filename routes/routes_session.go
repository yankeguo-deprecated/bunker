/**
 * routes_session.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"path/filepath"

	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/web"
)

// GetSessionFile get sessions replay
func GetSessionFile(ctx *web.Context, db *models.DB, cfg types.Config) {
	var err error
	id := ctx.Params(":id")
	s := models.Session{}
	if err = db.First(&s, id).Error; err != nil || s.ID == 0 {
		ctx.PlainText(404, []byte("Not Found"))
		return
	}
	ctx.ServeFile(filepath.Join(cfg.SSHD.ReplayDir, s.ReplayFile))
}

// GetSessionReplay get sessions replay
func GetSessionReplay(ctx *web.Context, db *models.DB) {
	ctx.Data["SessionID"] = ctx.Params(":id")
	ctx.HTML(200, "sessions/replay")
}
