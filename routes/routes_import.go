/**
 * routes_import.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"fmt"

	"github.com/yankeguo/bunker/models"
	"github.com/yankeguo/bunker/utils"
	"landzero.net/x/net/web"
)

// PostImportSSHConfig post import ssh config
func PostImportSSHConfig(ctx *web.Context, db *models.DB) {
	c, err := ctx.Req.Body().Bytes()
	if err != nil {
		ctx.PlainText(500, []byte(err.Error()))
		return
	}

	ls := utils.ParseSSHConfig(c)
	for _, e := range ls {
		db.Assign(map[string]interface{}{
			"is_auto": utils.False,
			"address": e.Address,
		}).FirstOrCreate(&models.Server{}, map[string]interface{}{
			"name": e.Name,
		})
	}

	ctx.PlainText(200, []byte(fmt.Sprintf("OK, imported %d", len(ls))))
}
