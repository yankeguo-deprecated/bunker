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
)

// Server server model
type Server struct {
	Model
	GroupID     uint   `orm:"index" json:"groupId"`     // server group id
	Name        string `orm:"unique_index" json:"name"` // server name, hostname
	Address     string `orm:"" json:"address"`          // host:ip of ssh port
	Desc        string `orm:"type:text" json:"desc"`    // extra decription
	Fingerprint string `orm:"index" json:"fingerprint"` // fingerprint of host key, sha256 fingerprint
}

// BeforeSave before save callback
func (s *Server) BeforeSave() (err error) {
	if !NamePattern.MatchString(s.Name) {
		err = errors.New("invalid field server.name")
	}
	return
}
