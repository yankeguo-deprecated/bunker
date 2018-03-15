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
	Env     string        `toml:"env"`     // application environment
	Secret  string        `toml:"secret"`  // secret of CSRF
	Title   string        `toml:"title"`   // site title
	Domain  string        `toml:"domain"`  // domain name for this site, for display
	DB      DBConfig      `toml:"db"`      // db config
	HTTP    HTTPConfig    `toml:"http"`    // http config
	SSHD    SSHDConfig    `toml:"sshd"`    // sshd config
	SSH     SSHConfig     `toml:"ssh"`     // ssh config
	Sandbox SandboxConfig `toml:"sandbox"` // sandbox config
	Consul  ConsulConfig  `toml:"consul"`  // consul config
}

// DBConfig config for DB
type DBConfig struct {
	File string `toml:"file"` // sqlite3 file
}

// HTTPConfig config for http
type HTTPConfig struct {
	Host   string `toml:"host"`   // host for http
	Port   int    `toml:"port"`   // port for http
	Secure bool   `toml:"secure"` // this will enable secure cookie
}

// SSHDConfig config for sshd
type SSHDConfig struct {
	Host       string `toml:"host"`        // host for sshd
	Port       int    `toml:"port"`        // port for sshd
	PrivateKey string `toml:"private_key"` // private key file, for sshd host key
	ReplayDir  string `toml:"replay_dir"`  // dir for replayfiles
}

// SSHConfig config for ssh
type SSHConfig struct {
	PrivateKey string `toml:"private_key"` // private key file, for ssh clien key
}

// SandboxConfig sandbox config
type SandboxConfig struct {
	Image   string `toml:"image"`
	DataDir string `toml:"datadir"`
}

// ConsulConfig consul config
type ConsulConfig struct {
	Enable bool `toml:"enable"`
}
