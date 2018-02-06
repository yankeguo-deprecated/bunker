/**
 * types/config.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package types

// Config config struct for Bunker, mapped to config.yaml
type Config struct {
	Env    string      `toml:"env"`    // application environment
	Title  string      `toml:"title"`  // site title
	Domain string      `toml:"domain"` // domain name for this site, for display
	DB     DBConfig    `toml:"db"`     // db config
	HTTP   HTTPConfig  `toml:"http"`   // http config
	SSHD   SSHDConfig  `toml:"sshd"`   // sshd config
	SSH    SSHConfig   `toml:"ssh"`    // ssh config
	Redis  RedisConfig `toml:"redis"`  // redis config
}

// RedisConfig redis config
type RedisConfig struct {
	URL string `toml:"url"`
}

// DBConfig config for DB
type DBConfig struct {
	URL string `toml:"url"` // mysql url (golang dsn)
}

// HTTPConfig config for http
type HTTPConfig struct {
	Host string `toml:"host"` // host for http
	Port int    `toml:"port"` // port for http
}

// SSHDConfig config for sshd
type SSHDConfig struct {
	Host       string `toml:"host"`        // host for sshd
	Port       int    `toml:"port"`        // port for sshd
	PrivateKey string `toml:"private_key"` // private key file, for sshd host key
}

// SSHConfig config for ssh
type SSHConfig struct {
	PrivateKey string `toml:"private_key"` // private key file, for ssh clien key
}
