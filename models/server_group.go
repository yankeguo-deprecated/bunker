/**
 * models/server_group.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

// ServerGroup servergroup
type ServerGroup struct {
	Model
	Name string `orm:"unique_index" json:"name"` // name
}

// ServerGroupRef server to servergroup relations
type ServerGroupRef struct {
	ServerID      uint `orm:"not null;unique_index:idx_server_server_group" json:"serverId"`      // server id
	ServerGroupID uint `orm:"not null;unique_index:idx_server_server_group" json:"serverGroupId"` // servergroup id
}
