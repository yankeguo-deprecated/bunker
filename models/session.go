/**
 * session.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package models

import (
	"fmt"
	"path/filepath"
	"time"
)

// Session recorded ssh session
type Session struct {
	Model
	UserAccount string     `orm:"index" json:"userAccount"`
	Command     string     `orm:"" json:"command"`
	StartedAt   time.Time  `orm:"index" json:"startedAt"`
	EndedAt     *time.Time `orm:"index" json:"endedAt"`
	IsRecorded  bool       `orm:"" json:"isRecorded"`
	ReplayFile  string     `orm:"" json:"-"`
}

// GenerateReplayFile generate replay file
func (s Session) GenerateReplayFile() string {
	y, m, d := s.StartedAt.Date()
	return filepath.Join(
		fmt.Sprintf("%04d", y),
		fmt.Sprintf("%02d", m),
		fmt.Sprintf("%02d", d),
		fmt.Sprintf("%08x", s.ID),
	)
}
