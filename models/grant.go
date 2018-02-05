/**
 * models/grant.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"errors"
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
	CreaterID  uint       `orm:"not null;index" json:"createrId"`                   // created by user id
	UserID     uint       `orm:"not null;index" json:"sourceId"`                    // user id or usergroup id
	TargetID   uint       `orm:"not null;index:idx_grant_target" json:"targetId"`   // server id or servergroup id
	TargetType int        `orm:"not null;index:idx_grant_target" json:"targetType"` // target type, 1 - server, 2 - servergroup
	TargetUser string     `orm:"not null" json:"targetUser"`                        // target user
	ExpiresAt  *time.Time `orm:"index" json:"expiresAt"`                            // grant expires at
}

// BeforeSave before save callback
func (g *Grant) BeforeSave() (err error) {
	if !NamePattern.MatchString(g.TargetUser) {
		err = errors.New("invalid field grant.target_user")
	}
	return
}
