/**
 * migrate.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/cli"
	"ireul.com/toml"
)

var migrateCommand = cli.Command{
	Name:   "migrate",
	Usage:  "migrate the database",
	Action: execMigrateCommand,
}

func execMigrateCommand(c *cli.Context) (err error) {
	cfg := types.BunkerConfig{}
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
