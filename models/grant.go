/**
 * models/grant.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"time"
)

// Grant grant
type Grant struct {
	Model
	UserID     uint       `orm:"not null;index" json:"userId"`     // user id or usergroup id
	ServerName string     `orm:"not null;index" json:"serverName"` // target server name
	TargetUser string     `orm:"not null;index" json:"targetUser"` // target user
	ExpiresAt  *time.Time `orm:"index" json:"expiresAt"`           // grant expires at
}
