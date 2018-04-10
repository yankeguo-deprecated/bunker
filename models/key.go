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
)

// Key key represents a ssh public key for user
type Key struct {
	Model
	Name        string     `orm:"not null" json:"name"`                     // name for this ssh key, for memorize
	UserID      uint       `orm:"not null;index" json:"userId"`             // user id
	Fingerprint string     `orm:"not null;unique_index" json:"fingerprint"` // fingerprint of public key, sha256 fingerprint
	UsedAt      *time.Time `orm:"" json:"usedAt"`                           // last seen at
	IsSandbox   int        `orm:"not null;default:0" json:"is_sandbox"`     // is sandbox
}
