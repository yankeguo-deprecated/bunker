/**
 * models/group.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"errors"
)

// Group servergroup
type Group struct {
	Model
	Name string `orm:"unique_index" json:"name"` // name
}

// BeforeSave before save callback
func (g *Group) BeforeSave() (err error) {
	if !NamePattern.MatchString(g.Name) {
		err = errors.New(`invalid field group.name, allows 3-15 letters, numbers, "-" or "_"`)
	}
	return
}
