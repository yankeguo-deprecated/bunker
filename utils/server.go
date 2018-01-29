/**
 * utils/server.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"sync"
)

// Server abstract bunker.SSHD server and bunker.HTTP server
type Server interface {
	ListenAndServe() error
	Shutdown() error
}

// RunServers runs multiple utils.Server
func RunServers(servers ...Server) error {
	wg := sync.WaitGroup{}
	errs := make([]error, 0)
	for _, s := range servers {
		if s != nil {
			wg.Add(1)
			var server = s
			go func() {
				defer wg.Done()
				errs = append(errs, server.ListenAndServe())
			}()
		}
	}
	wg.Wait()
	return ComposeError(errs...)
}

// ShutdownServers shutdown multiple utils.Server
func ShutdownServers(servers ...Server) error {
	errs := make([]error, 0)
	for _, s := range servers {
		if s != nil {
			errs = append(errs, s.Shutdown())
		}
	}
	return ComposeError(errs...)
}
