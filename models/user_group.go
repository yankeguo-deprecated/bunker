/**
 * models/user_group.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

// UserGroup user group
type UserGroup struct {
	Model
	Name string `json:"name"` // name of user group
}

// UserGroupRef user to usergroup relations
type UserGroupRef struct {
	UserID      uint `orm:"not null;unique_index:idx_user_user_group" json:"userId"`      // user id
	UserGroupID uint `orm:"not null;unique_index:idx_user_user_group" json:"userGroupId"` // usergroup id
}
