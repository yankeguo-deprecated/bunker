/**
 * web.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
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
	cfg := types.BunkerConfig{}
	if _, err = toml.DecodeFile(c.GlobalString("config"), &cfg); err != nil {
		return
	}
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	w := createWeb(cfg)
	routes.Mount(w)
	w.Map(db)
	w.Run(cfg.Port)
	return
}

func createWeb(cfg types.BunkerConfig) *web.Web {
	w := web.New()
	w.SetEnv(cfg.Env)
	w.Use(web.Logger())
	w.Use(web.Recovery())
	if w.Env() == web.DEV {
		w.Use(web.Static("public"))
		w.Use(web.Renderer())
	} else {
		w.Use(web.Static("public", web.StaticOptions{BinFS: true}))
		w.Use(web.Renderer(web.RenderOptions{BinFS: true}))
	}
	w.Use(func(ctx *web.Context) {
		ctx.Data["Version"] = VERSION
	})
	w.Map(cfg)
	return w
}
