/**
 * web.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"fmt"
	"net/http"

	"ireul.com/bunker/models"
	"ireul.com/bunker/routes"
	"ireul.com/bunker/types"
	"ireul.com/web"
)

// createHTTPServer create the web instance
func createHTTPServer(cfg types.Config) (h *http.Server, err error) {
	// create the DB
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	// create web instance
	w := web.New()
	// set environment
	w.SetEnv(cfg.Env)
	// basic components
	w.Use(web.Logger())
	w.Use(web.Recovery())
	// static assets and templates
	if w.Env() == web.DEV {
		w.Use(web.Static("public"))
		w.Use(web.Renderer())
	} else {
		w.Use(web.Static("public", web.StaticOptions{BinFS: true}))
		w.Use(web.Renderer(web.RenderOptions{BinFS: true}))
	}
	// set version in ctx.Data
	w.Use(func(ctx *web.Context) {
		ctx.Data["Version"] = VERSION
	})
	// map Config
	w.Map(cfg)
	// map the DB
	w.Map(db)
	// mount routes
	routes.Mount(w)
	h = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler: w,
	}
	return
}
