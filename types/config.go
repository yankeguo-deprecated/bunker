/**
 * types/config.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package types

// BunkerConfig config struct for Bunker, mapped to config.yaml
type BunkerConfig struct {
	Env         string `toml:"env"`          // application environment
	Port        int    `toml:"port"`         // http port, including websocket
	DatabaseURL string `toml:"database_url"` // database url
}
