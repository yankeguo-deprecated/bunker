/**
 * auto.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"fmt"
	"log"
	"time"

	capi "github.com/hashicorp/consul/api"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
)

// Auto auto server registry
type Auto struct {
	Config    types.Config
	client    *capi.Client
	db        *models.DB
	lastIndex uint64
	stopFlag  bool
	done      chan bool
}

// NewAuto new auto
func NewAuto(config types.Config) *Auto {
	return &Auto{Config: config, done: make(chan bool, 1)}
}

// ListenAndServe implements utils.Server
func (a *Auto) ListenAndServe() (err error) {
	if !a.Config.Consul.Enable {
		return
	}
	if a.db == nil {
		if a.db, err = models.NewDB(a.Config); err != nil {
			return
		}
	}
	if a.client == nil {
		if a.client, err = capi.NewClient(capi.DefaultConfig()); err != nil {
			return
		}
	}
	for {
		a.update()
		if a.stopFlag {
			break
		}
		time.Sleep(time.Second * 3)
	}
	a.done <- true
	return
}

func (a *Auto) update() {
	var err error
	var ns []*capi.Node
	var qm *capi.QueryMeta
	if ns, qm, err = a.client.Catalog().Nodes(&capi.QueryOptions{
		WaitIndex: a.lastIndex,
		WaitTime:  time.Second * 30,
	}); err != nil {
		a.lastIndex = 0
		log.Println("Auto:", err)
		return
	}
	a.lastIndex = qm.LastIndex
	// update database
	for _, n := range ns {
		a.db.Assign(map[string]interface{}{
			"address": fmt.Sprintf("%s:22", n.Address),
			"is_auto": true,
		}).FirstOrCreate(&models.Server{}, map[string]interface{}{
			"name": n.Node,
		})
	}
	// delete missing
	ss := []models.Server{}
	if err = a.db.Find(&ss, "is_auto = ?", true).Error; err != nil {
		a.lastIndex = 0
		return
	}
L1:
	for _, s := range ss {
		for _, n := range ns {
			if n.Node == s.Name {
				continue L1
			}
		}
		a.db.Delete(&models.Server{}, "name = ?", s.Name)
	}
}

// Shutdown implements utils.Server
func (a *Auto) Shutdown() (err error) {
	a.stopFlag = true
	<-a.done
	return
}
