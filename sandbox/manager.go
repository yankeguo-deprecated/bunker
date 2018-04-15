/**
 * sandbox/manager.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/docker/docker/client"

	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/yankeguo/bunker/types"
)

const dirPerm = os.FileMode(0750)

// GetContainerName get container name for account
func GetContainerName(account string) string {
	return fmt.Sprintf("sandbox-%s", account)
}

// Manager manager interface
type Manager interface {
	FindOrCreate(account string) (Sandbox, error)
}

type manager struct {
	Config types.Config
	mutex  *sync.Mutex
	client *client.Client
}

// NewManager new manager
func NewManager(cfg types.Config) (m Manager, err error) {
	var c *client.Client
	if c, err = client.NewEnvClient(); err != nil {
		return
	}
	return &manager{
		Config: cfg,
		mutex:  &sync.Mutex{},
		client: c,
	}, nil
}

// FindOrCreate find or create a sandbox
func (m *manager) FindOrCreate(account string) (s Sandbox, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	name := GetContainerName(account)
	// ensure dir
	uDir := path.Join(m.Config.Sandbox.DataDir, name)
	sDir := path.Join(m.Config.Sandbox.DataDir, "shared")
	if err = os.MkdirAll(uDir, dirPerm); err != nil {
		return
	}
	if err = os.MkdirAll(sDir, dirPerm); err != nil {
		return
	}
	// find containers
	fts := filters.NewArgs()
	fts.Add("name", name)
	var list []dtypes.Container
	if list, err = m.client.ContainerList(context.Background(), dtypes.ContainerListOptions{All: true, Filters: fts}); err != nil {
		return
	}
	var running bool
	var created bool
	// create if not found
	if len(list) == 0 {
		if _, err = m.client.ContainerCreate(
			context.Background(),
			&container.Config{
				Hostname: fmt.Sprintf("%s.sandbox", account),
				Image:    m.Config.Sandbox.Image,
			},
			&container.HostConfig{
				Binds: []string{
					fmt.Sprintf("%s:/root", uDir),
					fmt.Sprintf("%s:/shared", sDir),
				},
				RestartPolicy: container.RestartPolicy{
					Name: "always",
				},
			},
			&network.NetworkingConfig{},
			name,
		); err != nil {
			return
		}
	} else {
		created = true
		running = list[0].State == "running"
	}
	// create the sandbox
	s = &sandbox{
		name:   name,
		client: m.client,
	}
	// start if not running
	if !running {
		if err = s.Start(); err != nil {
			return
		}
	}
	// create ssh keys
	if !created {
		if err = s.GenerateSSHKey(); err != nil {
			return
		}
	}
	// get ssh keys
	return
}
