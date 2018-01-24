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

	"ireul.com/cli"
	_ "ireul.com/mysql"
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
		webCommand,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln("Failed to run,", err)
	}
}
