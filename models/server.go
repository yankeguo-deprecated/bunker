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
	Name    string     `orm:"not null;unique_index" json:"name"`      // server name, hostname
	Address string     `orm:"not null;" json:"address"`               // host:ip of ssh port
	UsedAt  *time.Time `orm:"" json:"usedAt"`                         // last used at
	IsAuto  bool       `orm:"not null;default:'false'" json:"isAuto"` // is consul
}

// BeforeSave before save callback
func (s *Server) BeforeSave() (err error) {
	if !NamePattern.MatchString(s.Name) {
		err = errors.New("invalid field server.name")
	}
	return
}
