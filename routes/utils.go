/**
 * routes/utils.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"fmt"
	"net/url"
	"time"

	"landzero.net/x/com"
	"landzero.net/x/time/ago"
)

// Pagination page info
type Pagination struct {
	Pages []PageItem
}

// PageItem page item
type PageItem struct {
	Title      string
	URL        string
	IsCurrent  bool
	IsDisabled bool
}

// CreatePagination create page info, curr is 0-based
func CreatePagination(totalCount int, perPage int, currentPage int, baseurl string) (p Pagination) {
	p.Pages = []PageItem{}
	// calculate total page
	totalPage := totalCount / perPage
	if totalCount%perPage > 0 {
		totalPage = totalPage + 1
	}
	if totalPage <= 1 {
		return
	}
	// fix current page
	if currentPage < 0 {
		currentPage = 0
	}
	if currentPage >= totalPage {
		currentPage = totalPage - 1
	}
	// decide should display first
	if currentPage > 5 {
		p.Pages = append(p.Pages, PageItem{
			Title:      "<<",
			URL:        fmt.Sprintf("%s?page=%d", baseurl, 1),
			IsDisabled: false,
			IsCurrent:  false,
		})
	}
	// show 5 pages
	for i := currentPage - 5; i < currentPage+6; i++ {
		if i < 0 {
			continue
		}
		if i >= totalPage {
			break
		}
		p.Pages = append(p.Pages, PageItem{
			Title:     fmt.Sprintf("%d", i+1),
			URL:       fmt.Sprintf("%s?page=%d", baseurl, i+1),
			IsCurrent: i == currentPage,
		})
	}
	// decide should display last
	if currentPage+5 < totalPage {
		p.Pages = append(p.Pages, PageItem{
			Title: ">>",
			URL:   fmt.Sprintf("%s?page=%d", baseurl, totalPage),
		})
	}
	return
}

// TimeAgo time ago in chinese words
func TimeAgo(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return ago.Chinese.Format(*t)
}

// PrettyTime pretty time
func PrettyTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
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
