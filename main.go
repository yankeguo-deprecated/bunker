/**
 * main.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"log"
	"os"

	"ireul.com/bunker/models"
	"ireul.com/bunker/routes"
	"ireul.com/bunker/types"
	"ireul.com/cli"
	_ "ireul.com/mysql"
	"ireul.com/toml"
	"ireul.com/web"
)

// VERSION version string of current source code
const VERSION = "1.0.0"

func main() {
	app := cli.NewApp()
	app.Name = "bunker"
	app.Usage = "Enterprise Bastion System"
	app.Version = VERSION
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "config.toml",
			Usage: "config file",
		},
	}
	app.Commands = []cli.Command{
		migrateCommand,
		runCommand,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln("Failed to run,", err)
	}
}

var migrateCommand = cli.Command{
	Name:   "migrate",
	Usage:  "migrate the database",
	Action: execMigrateCommand,
}

func execMigrateCommand(c *cli.Context) (err error) {
	cfg := types.Config{}
	if _, err = toml.DecodeFile(c.GlobalString("config"), &cfg); err != nil {
		return
	}
	var db *models.DB
	if db, err = models.NewDB(cfg); err != nil {
		return
	}
	err = db.AutoMigrate()
	return
}

var runCommand = cli.Command{
	Name:   "run",
	Usage:  "run the server",
	Action: runCommandHandler,
}

func runCommandHandler(c *cli.Context) (err error) {
	// parse config.toml
	cfg := types.Config{}
	if _, err = toml.DecodeFile(c.GlobalString("config"), &cfg); err != nil {
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
	// run the web instance
	w.Run(cfg.HTTP.Host, cfg.HTTP.Port)
	return
}

// createWeb create the web instance
func createWeb(cfg types.Config) *web.Web {
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
	// mount routes
	routes.Mount(w)
	return w
}
