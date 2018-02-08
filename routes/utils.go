/**
 * routes/utils.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"time"

	"ireul.com/timeago"
)

// TimeAgo time ago in chinese words
func TimeAgo(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return timeago.Chinese.Format(*t)
}
