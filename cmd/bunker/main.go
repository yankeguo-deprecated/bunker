/**
 * cmd/bunker/main.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"io/ioutil"
	"log"
	"os"

	"ireul.com/bunker"
	"ireul.com/bunker/types"
	"ireul.com/bunker/utils"
	"ireul.com/cli"
)

var migrateCommand = cli.Command{
	Name:  "migrate",
	Usage: "migrate the database",
	Action: func(ctx *cli.Context) (err error) {
		var b *bunker.Bunker
		if b, err = createBunker(ctx); err != nil {
			return
		}
		return b.Migrate()
	},
}

var createUserCommand = cli.Command{
	Name:  "create-user",
	Usage: "create a new user",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "account",
			Usage: "account name of user",
		},
		cli.StringFlag{
			Name:  "password",
			Usage: "password of user",
		},
		cli.StringFlag{
			Name:  "key",
			Usage: "public key of user",
		},
		cli.BoolFlag{
			Name:  "admin",
			Usage: "is admin",
		},
	},
	Action: func(ctx *cli.Context) (err error) {
		var b *bunker.Bunker
		if b, err = createBunker(ctx); err != nil {
			return
		}
		option := bunker.CreateUserOption{
			Account:  ctx.String("account"),
			Password: ctx.String("password"),
			IsAdmin:  ctx.Bool("admin"),
		}
		if len(ctx.String("key")) > 0 {
			if option.PublicKey, err = ioutil.ReadFile(ctx.String("key")); err != nil {
				return
			}
		}
		return b.CreateUser(option)
	},
}

var createServerCommand = cli.Command{
	Name:  "create-server",
	Usage: "create a server",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "name",
			Usage: "name of server",
		},
		cli.StringFlag{
			Name:  "address",
			Usage: "IP:PORT of server",
		},
		cli.StringFlag{
			Name:  "group",
			Usage: "name of group",
		},
	},
	Action: func(ctx *cli.Context) (err error) {
		var b *bunker.Bunker
		if b, err = createBunker(ctx); err != nil {
			return
		}
		return b.CreateServer(bunker.CreateServerOption{
			Name:    ctx.String("name"),
			Address: ctx.String("address"),
			Group:   ctx.String("group"),
		})
	},
}

var createGrantCommand = cli.Command{
	Name:  "create-grant",
	Usage: "create a grant",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "server",
			Usage: "name of server",
		},
		cli.StringFlag{
			Name:  "group",
			Usage: "name of group",
		},
		cli.StringFlag{
			Name:  "user",
			Usage: "login of user",
		},
		cli.StringFlag{
			Name:  "target-user",
			Usage: "target user name",
		},
		cli.UintFlag{
			Name:  "expires-in",
			Usage: "expires in seconds",
		},
	},
	Action: func(ctx *cli.Context) (err error) {
		var b *bunker.Bunker
		if b, err = createBunker(ctx); err != nil {
			return
		}
		return b.CreateGrant(bunker.CreateGrantOption{
			Group:      ctx.String("group"),
			Server:     ctx.String("server"),
			User:       ctx.String("user"),
			TargetUser: ctx.String("target-user"),
			ExpiresIn:  ctx.Uint("expires-in"),
		})
	},
}

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the server",
	Action: func(ctx *cli.Context) (err error) {
		var b *bunker.Bunker
		if b, err = createBunker(ctx); err != nil {
			return
		}
		return b.ListenAndServe()
	},
}

func createBunker(ctx *cli.Context) (b *bunker.Bunker, err error) {
	var cfg types.Config
	if cfg, err = utils.DecodeConfigFile(ctx.GlobalString("config")); err != nil {
		return
	}
	b = bunker.NewBunker(cfg)
	return
}

func main() {
	app := cli.NewApp()
	app.Name = "bunker"
	app.Usage = "Enterprise Bastion System"
	app.Version = bunker.VERSION
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
		createUserCommand,
		createServerCommand,
		createGrantCommand,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}
