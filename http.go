/**
 * http.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package bunker

import (
	"context"
	"fmt"
	"net/http"

	"ireul.com/bunker/models"
	"ireul.com/bunker/routes"
	"ireul.com/bunker/types"
	"ireul.com/web"
)

// HTTP http server of bunker
type HTTP struct {
	Config types.Config // config
	server *http.Server // core http.Server
	web    *web.Web     // ireul.com/web instance
	db     *models.DB   // models.DB
}

// NewHTTP create the HTTP server
func NewHTTP(config types.Config) *HTTP {
	return &HTTP{
		Config: config,
	}
}

// ListenAndServe initialize the HTTP and invoke internal http.Server#ListenAndServe, http.ErrServerClosed will be muted
func (h *HTTP) ListenAndServe() (err error) {
	// initialize DB if needed
	if h.db == nil {
		if h.db, err = models.NewDB(h.Config); err != nil {
			return
		}
	}
	// initialize Web if needed
	if h.web == nil {
		h.web = web.New()
		h.web.SetEnv(h.Config.Env)
		h.web.Use(web.Logger())
		h.web.Use(web.Recovery())
		h.web.Use(web.Static("public", web.StaticOptions{BinFS: h.web.Env() != web.DEV}))
		h.web.Use(web.Renderer(web.RenderOptions{BinFS: h.web.Env() != web.DEV}))
		h.web.Map(h.Config)
		h.web.Map(h.db)
		routes.Mount(h.web)
	}
	// create the http.Server
	if h.server == nil {
		h.server = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", h.Config.HTTP.Host, h.Config.HTTP.Port),
			Handler: h.web,
		}
	}
	err = h.server.ListenAndServe()
	if err == http.ErrServerClosed {
		err = nil
	}
	return
}

// Shutdown shutdown the server
func (h *HTTP) Shutdown() (err error) {
	if h.server != nil {
		return h.server.Shutdown(context.Background())
	}
	return
}
