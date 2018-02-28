/**
 * routes/utils.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"net/url"
	"time"

	"ireul.com/com"
	"ireul.com/timeago"
)

// TimeAgo time ago in chinese words
func TimeAgo(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return timeago.Chinese.Format(*t)
}

// AppendQuery build a new url with query appended
func AppendQuery(s string, c ...interface{}) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if len(c)%2 != 0 {
		return s
	}
	q := u.Query()
	for i := 0; i < len(c); i = i + 2 {
		q.Set(com.ToStr(c[i]), com.ToStr(c[i+1]))
	}
	u.RawQuery = q.Encode()
	return u.String()
}
