/**
 * ssh.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// SSHConfigEntry ssh config entry
type SSHConfigEntry struct {
	Name    string
	Address string
}

// ParseSSHConfig parse ssh config
func ParseSSHConfig(c []byte) []SSHConfigEntry {
	ret := []SSHConfigEntry{}
	ls := ParseSSHLines(c)
	var host string
	var hostname string
	var port string
	var add = func() {
		// already has a host recorded
		if len(host) > 0 {
			if len(hostname) > 0 {
				if len(port) == 0 {
					port = "22"
				}
				ret = append(ret, SSHConfigEntry{
					Name:    host,
					Address: fmt.Sprintf("%s:%s", hostname, port),
				})
			}
		}
		host = ""
		hostname = ""
		port = ""
	}
	for _, l := range ls {
		if l[0] == "host" {
			add()
			host = l[1]
		}
		if l[0] == "hostname" {
			hostname = l[1]
		}
		if l[0] == "port" {
			port = l[1]
		}
	}
	add()
	return ret
}

// ParseSSHLines parse ssh lines
func ParseSSHLines(c []byte) [][]string {
	ret := [][]string{}
	var err error
	r := bufio.NewReader(bytes.NewReader(c))
	for {
		var l []byte
		l, _, err = r.ReadLine()
		if err != nil {
			break
		}
		ls := strings.TrimSpace(string(l))
		lss := strings.SplitN(ls, " ", 2)
		if len(lss) != 2 {
			lss = strings.SplitN(ls, "\t", 2)
			if len(lss) != 2 {
				continue
			}
		}
		ret = append(ret, []string{
			strings.ToLower(strings.TrimSpace(lss[0])),
			strings.TrimSpace(lss[1]),
		})
	}
	return ret
}
