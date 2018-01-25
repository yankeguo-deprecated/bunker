/**
 * main.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/cli"
	_ "ireul.com/mysql"
	"ireul.com/sshd"
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
	// create the web instance
	var h *http.Server
	if h, err = createHTTPServer(cfg); err != nil {
		return
	}
	var s *sshd.Server
	if s, err = createSSHDServer(cfg); err != nil {
		return
	}
	// signal handler
	schan := make(chan os.Signal, 1)
	signal.Notify(schan, os.Interrupt, syscall.SIGTERM)
	// run servers
	wait := sync.WaitGroup{}
	wait.Add(2)
	go func() {
		defer wait.Done()
		log.Println("http server starting:", h.Addr)
		log.Println("http server closed:", h.ListenAndServe())
	}()
	go func() {
		defer wait.Done()
		log.Println("sshd server starting:", s.Addr)
		log.Println("sshd server closed:", s.ListenAndServe())
	}()
	// wait signals and shutdown
	log.Println("signal received:", <-schan)
	h.Shutdown(context.Background())
	s.Shutdown(context.Background())
	wait.Wait()
	return
}
