/**
 * sshd.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package main

import (
	"fmt"

	"ireul.com/bunker/types"
	"ireul.com/sshd"
)

func createSSHDServer(cfg types.Config) (s *sshd.Server, err error) {
	s = &sshd.Server{
		Addr: fmt.Sprintf("%s:%d", cfg.SSHD.Host, cfg.SSHD.Port),
		Handler: func(sess sshd.Session) {
		},
		PublicKeyHandler: func(ctx sshd.Context, key sshd.PublicKey) bool {
			return false
		},
	}
	return
}
