/**
 * utils/decode.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"ireul.com/bunker/types"
	"ireul.com/toml"
)

// DecodeConfigFile decode a toml config file to types.BunkerConfig
func DecodeConfigFile(file string) (config types.BunkerConfig, err error) {
	_, err = toml.DecodeFile(file, &config)
	return
}
