/**
 * models/key.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"time"

	"ireul.com/orm"
)

// Key key represents a ssh public key for user
type Key struct {
	orm.Model

	Name        string     `json:"name"`                           // name for this ssh key, for memorize
	UserID      uint       `orm:"index" json:"userId"`             // user id
	Fingerprint string     `orm:"unique_index" json:"fingerprint"` // fingerprint of public key, sha256 fingerprint
	UsedAt      *time.Time `json:"usedAt"`                         // last seen at
}
