/**
 *Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 *This software is released under the MIT License.
 *https://opensource.org/licenses/MIT
 */

package sandbox

import (
	"fmt"
	"testing"

	"github.com/yankeguo/bunker/types"
)

func TestManagerFindOrCreate(t *testing.T) {
	var m Manager
	var err error
	if m, err = NewManager(types.Config{Sandbox: types.SandboxConfig{Image: "ireul/sandbox", DataDir: "/tmp/sandboxdata"}}); err != nil {
		t.Fatal(err)
	}
	var s Sandbox
	if s, err = m.FindOrCreate("test2"); err != nil {
		t.Fatal(err)
	}
	var out1 string
	if out1, err = s.GetSSHPublicKey(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(out1)
}
