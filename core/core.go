/**
 * core/core.go
 * bunker core system, handling websocket and ssh connections
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package core

import (
	"ireul.com/bunker/types"
	"ireul.com/websocket"
)

// Core the core system
type Core struct {
	Sessions map[string]*Session // all sessions recorded
}

// NewCore create a new core, the default core should be used normally
func NewCore(cfg types.BunkerConfig) (cr *Core, err error) {
	cr = &Core{}
	return
}

// HandleWebsocket handle the websocket connection
func (c *Core) HandleWebsocket(conn *websocket.Conn, sid string) {
}
