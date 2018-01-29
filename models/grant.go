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
	// GrantSourceUser source type - user
	GrantSourceUser = 1
	// GrantSourceUserGroup source type - usergroup
	GrantSourceUserGroup = 2
	// GrantTargetUser source type - user
	GrantTargetUser = 1
	// GrantTargetUserGroup source type - usergroup
	GrantTargetUserGroup = 2
)

// Grant grant
type Grant struct {
	Model
	CreaterID  uint       `orm:"not null;index" json:"createrId"`                   // created by user id
	SourceID   uint       `orm:"not null;index:idx_grant_source" json:"sourceId"`   // user id or usergroup id
	SourceType int        `orm:"not null;index:idx_grant_source" json:"sourceType"` // source type , 1 - user, 2 - usergroup
	TargetID   uint       `orm:"not null;index:idx_grant_target" json:"targetId"`   // server id or servergroup id
	TargetType int        `orm:"not null;index:idx_grant_target" json:"targetType"` // target type, 1 - server, 2 - servergroup
	TargetUser string     `orm:"not null" json:"targetUser"`                        // target user, comma seperated
	ExpiresAt  *time.Time `orm:"index" json:"expiresAt"`                            // grant expires at
}
