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
	"strconv"

	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/bunker/utils"
	"ireul.com/web"
	"ireul.com/web/session"
)

// SessionItem session item
type SessionItem struct {
	ID         uint
	User       string
	Command    string
	StartedAt  string
	EndedAt    string
	IsRecorded bool
}

// SessionsPerPage sessions per page
const SessionsPerPage = 50

// GetSessionsIndex get sessions index
func GetSessionsIndex(ctx *web.Context, db *models.DB, cfg types.Config) {
	ctx.Data["NavClass_Sessions"] = "active"
	var err error
	// calculate page 0 based
	var page int
	if page, err = strconv.Atoi(ctx.Query("page")); err != nil || page < 1 {
		page = 0
	} else {
		page = page - 1
	}
	// total count
	var count int
	db.Model(&models.Session{}).Count(&count)
	// create pagination
	ctx.Data["Pagination"] = CreatePagination(count, SessionsPerPage, page, ctx.URLFor("sessions"))
	// data
	ss := []models.Session{}
	db.Model(&models.Session{}).Order("id DESC").Offset(page * SessionsPerPage).Limit(SessionsPerPage).Find(&ss)
	out := []SessionItem{}
	for _, s := range ss {
		out = append(out, SessionItem{
			ID:         s.ID,
			User:       s.UserAccount,
			Command:    s.Command,
			StartedAt:  PrettyTime(&s.StartedAt),
			EndedAt:    PrettyTime(s.EndedAt),
			IsRecorded: utils.ToBool(s.IsRecorded),
		})
	}
	ctx.Data["Sessions"] = out
	ctx.HTML(200, "sessions/index")
}

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
func GetSessionReplay(ctx *web.Context, db *models.DB, fl *session.Flash) {
	var err error
	s := models.Session{}
	if err = db.First(&s, ctx.Params(":id")).Error; err != nil {
		fl.Error("没有找到操作记录")
		ctx.Redirect(ctx.URLFor("sessions"))
		return
	}
	ctx.Data["Session"] = s
	ctx.Data["Session_StartedAt"] = PrettyTime(&s.StartedAt)
	ctx.Data["Session_EndedAt"] = PrettyTime(s.EndedAt)
	ctx.HTML(200, "sessions/replay")
}
