/**
 * web.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"ireul.com/bunker/core"
	"ireul.com/bunker/models"
	"ireul.com/bunker/routes"
	"ireul.com/bunker/types"
	"ireul.com/cli"
	"ireul.com/toml"
	"ireul.com/web"
)

var webCommand = cli.Command{
	Name:   "web",
	Usage:  "start the web server",
	Action: execWebCommand,
}

func execWebCommand(c *cli.Context) (err error) {
	// parse config.toml
	cfg := types.BunkerConfig{}
	if _, err = toml.DecodeFile(c.GlobalString("config"), &cfg); err != nil {
		return
	}
	// create the core
	var cr *core.Core
	if cr, err = core.NewCore(cfg); err != nil {
		return
	}
	// create the DB
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	// create the web instance
	w := createWeb(cfg)
	// map the DB
	w.Map(db)
	// map the Core
	w.Map(cr)
	// run the web instance
	w.Run(cfg.Port)
	return
}

// createWeb create the web instance
func createWeb(cfg types.BunkerConfig) *web.Web {
	w := web.New()
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
	// map BunkerConfig
	w.Map(cfg)
	// mount routes
	routes.Mount(w)
	return w
}
