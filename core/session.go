/**
 * core/session.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package core

import (
	"golang.org/x/crypto/ssh"
	"ireul.com/websocket"
)

// Session one-to-one mapping from websocket connection to ssh session
type Session struct {
	State         int             // session status
	ID            string          // session id
	UserID        uint            // user id in database, record only
	ServerID      uint            // server id in database, record only
	ServerAddress string          // address:port of target server
	Conn          *websocket.Conn // websocket connection
	Client        *ssh.Client     // ssh client
	Session       *ssh.Session    // ssh session
}
