/**
 * sandbox/scripts.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package sandbox

import (
	"bytes"
	"log"
	"text/template"

	"ireul.com/com"
)

const scriptGenerateSSHKey = `#!/bin/bash
# write README
echo "这是你的私人沙箱环境，沙箱内的 .ssh/id_rsa.pub 和 .ssh/config 文件会自动更新" > /root/README

# create /root/.ssh
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cd /root/.ssh

# create id_rsa
ssh-keygen -f /root/.ssh/id_rsa -t rsa -N ''

# write README
echo "id_rsa 和 id_rsa.pub 受 Bunker 管理，请勿修改" > README
`

const tplSSHConfig = `#!/bin/bash
# remove .ssh/config
rm -f /root/.ssh/config

# create new .ssh/config
{{range .Entries}}
echo "Host {{.Name}}" >> /root/.ssh/config
echo "  HostName {{.Host}}" >> /root/.ssh/config
echo "  Port {{.Port}}" >> /root/.ssh/config
echo "  User {{.User}}" >> /root/.ssh/config
{{end}}
`

// SSHEntry a entry in ssh_config
type SSHEntry struct {
	Name string
	Host string
	Port uint
	User string
}

func createScript(name string, tmpl string, data com.Map) string {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		log.Fatal(err)
	}
	buf := &bytes.Buffer{}
	t.Execute(buf, data)
	return buf.String()
}

// ScriptSeedSSHConfig create a script for seeding .ssh/config
func ScriptSeedSSHConfig(entries []SSHEntry) string {
	return createScript(
		"seed-ssh-config",
		tplSSHConfig,
		com.NewMap("Entries", entries),
	)
}
