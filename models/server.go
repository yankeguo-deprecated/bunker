/**
 * models/server.go
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

// Server server model
type Server struct {
	Model
	GroupName   string     `orm:"not null;index" json:"groupName"` // server group id
	Name        string     `orm:"unique_index" json:"name"`        // server name, hostname
	Address     string     `orm:"" json:"address"`                 // host:ip of ssh port
	Desc        string     `orm:"type:text" json:"desc"`           // extra decription
	Fingerprint string     `orm:"index" json:"fingerprint"`        // fingerprint of host key, sha256 fingerprint
	UsedAt      *time.Time `orm:"" json:"usedAt"`                  // last used at
}

// BeforeSave before save callback
func (s *Server) BeforeSave() (err error) {
	if !NamePattern.MatchString(s.Name) {
		err = errors.New("invalid field server.name")
	}
	return
}
