/**
 * main.go
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
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/bunker/utils"
	"ireul.com/cli"
	_ "ireul.com/mysql"
	"ireul.com/toml"
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
		createUserCommand,
		runCommand,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}

var migrateCommand = cli.Command{
	Name:   "migrate",
	Usage:  "migrate the database",
	Action: execMigrate,
}

func execMigrate(c *cli.Context) (err error) {
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

var createUserCommand = cli.Command{
	Name:   "create-user",
	Usage:  "create a new user",
	Action: execSeed,
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
}

func execSeed(c *cli.Context) (err error) {
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
	// create user
	u := &models.User{
		Account: c.String("account"),
		IsAdmin: c.Bool("admin"),
	}
	if err = u.SetPassword(c.String("password")); err != nil {
		return
	}
	if err = db.Create(u).Error; err != nil {
		return
	}
	// create public key
	if len(c.String("key")) > 0 {
		var r []byte
		if r, err = ioutil.ReadFile(c.String("key")); err != nil {
			return
		}
		var p ssh.PublicKey
		if p, _, _, _, err = ssh.ParseAuthorizedKey(r); err != nil {
			return
		}
		k := &models.Key{
			Name:        "main",
			UserID:      u.ID,
			Fingerprint: strings.TrimSpace(ssh.FingerprintSHA256(p)),
		}
		if err = db.Create(k).Error; err != nil {
			return
		}
	}
	return
}

var runCommand = cli.Command{
	Name:   "run",
	Usage:  "run the server",
	Action: execRun,
}

func execRun(c *cli.Context) (err error) {
	// parse config.toml
	cfg := types.Config{}
	if _, err = toml.DecodeFile(c.GlobalString("config"), &cfg); err != nil {
		return
	}
	// create bunker
	b := NewBunker(cfg)
	// signal handler
	schan := make(chan os.Signal, 1)
	signal.Notify(schan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-schan
		b.Shutdown()
	}()
	return b.Run()
}

// Bunker the bunker server
type Bunker struct {
	Config types.Config
	http   *HTTP
	sshd   *SSHD
}

// NewBunker create a new bunker instance
func NewBunker(config types.Config) *Bunker {
	return &Bunker{Config: config}
}

// Run run the server
func (b *Bunker) Run() (err error) {
	if b.http == nil {
		b.http = NewHTTP(b.Config)
	}
	if b.sshd == nil {
		b.sshd = NewSSHD(b.Config)
	}
	return utils.RunServers(b.http, b.sshd)
}

// Shutdown the internal servers
func (b *Bunker) Shutdown() (err error) {
	return utils.ShutdownServers(b.http, b.sshd)
}
