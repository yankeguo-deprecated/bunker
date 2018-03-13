/**
 * routes_import_test.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"testing"
)

const tcft = `Host sys.index.server3
Hostname 127.104.176.61
Port 22
User root
ServerAliveInterval 30

Host sys.index.server4
Hostname 127.104.175.44
Port 22
User root
ServerAliveInterval 30

Host sys.buy.db4s1
Hostname 127.104.154.61
Port 22
User root
ServerAliveInterval 30

Host sys.buy.db5m
Hostname 127.104.154.29
Port 22
User root
ServerAliveInterval 30

Host sys.buy.db5s1
Hostname 127.104.141.128
Port 22
User root
ServerAliveInterval 30

Host sys.buy.db6m
Hostname 127.104.146.229
Port 22
User root
ServerAliveInterval 30
`

func TestParseSSHConfig(t *testing.T) {
	ls := ParseSSHConfig([]byte(tcft))
	if len(ls) != 6 {
		t.Errorf("invalid len %d", len(ls))
	}
	if ls[5].Address != "127.104.146.229:22" {
		t.Errorf("invalid address")
	}
	if ls[5].Name != "sys.buy.db6m" {
		t.Errorf("invalid name")
	}
}
