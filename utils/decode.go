/**
 * utils/decode.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"github.com/yankeguo/bunker/types"
	"islandzero.net/x/encoding/toml"
)

// DecodeConfigFile decode a toml config file to types.Config
func DecodeConfigFile(file string) (config types.Config, err error) {
	_, err = toml.DecodeFile(file, &config)
	return
}
