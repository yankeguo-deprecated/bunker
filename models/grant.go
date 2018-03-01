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

const (
	// GrantTargetServer source type - user
	GrantTargetServer = 1
	// GrantTargetGroup source type - usergroup
	GrantTargetGroup = 2
)

// Grant grant
type Grant struct {
	Model
	UserID     uint       `orm:"not null;index" json:"userId"`                      // user id or usergroup id
	TargetName string     `orm:"not null;index:idx_grant_target" json:"targetName"` // server id or servergroup id
	TargetType int        `orm:"not null;index:idx_grant_target" json:"targetType"` // target type, 1 - server, 2 - servergroup
	TargetUser string     `orm:"not null" json:"targetUser"`                        // target user
	ExpiresAt  *time.Time `orm:"index" json:"expiresAt"`                            // grant expires at
}
