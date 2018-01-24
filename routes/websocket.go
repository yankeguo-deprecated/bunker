/**
 * websocket.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"net/http"

	"ireul.com/bunker/core"
	"ireul.com/web"
	"ireul.com/websocket"
)

// handle and upgrade websocket session, attatch to a session to target server
func handleWebSocketSession(w http.ResponseWriter, r web.Render, req *http.Request, cr *core.Core) {
	u := websocket.Upgrader{}
	c, err := u.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	// TODO: validate session and pass to core
	go cr.HandleWebsocket(c, "")
}
