/**
 *Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 *This software is released under the MIT License.
 *https://opensource.org/licenses/MIT
 */

package routes

import (
	"log"
	"testing"
)

func TestCreatePagination(t *testing.T) {
	p := CreatePagination(102, 10, 8, "example")
	for _, g := range p.Pages {
		log.Printf("%s, %v = %s", g.Title, g.IsCurrent, g.URL)
	}
}
