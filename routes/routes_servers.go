/**
 * routes/routes_server.go
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package routes

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/yankeguo/bunker/models"
	"github.com/yankeguo/bunker/types"
	"github.com/yankeguo/bunker/utils"
	"golang.org/x/crypto/ssh"
	"islandzero.net/x/net/web"
	"islandzero.net/x/net/web/session"
)

var clientKey string

// GenerateClientAuthorizedKey create authorized key string from client private key
func GenerateClientAuthorizedKey(cfg types.Config) string {
	if len(clientKey) > 0 {
		return clientKey
	}
	var err error
	var pk []byte
	var s ssh.Signer
	if pk, err = ioutil.ReadFile(cfg.SSH.PrivateKey); err != nil {
		return ""
	}
	if s, err = ssh.ParsePrivateKey(pk); err != nil {
		return ""
	}
	clientKey = string(ssh.MarshalAuthorizedKey(s.PublicKey()))
	return clientKey
}

// ServerItem server item
type ServerItem struct {
	ID        uint
	Name      string
	Address   string
	CreatedAt string
	UpdatedAt string
	IsAuto    bool
	UsedAt    string
}

// ServerItems slice of server item
type ServerItems []ServerItem

func (a ServerItems) Len() int           { return len(a) }
func (a ServerItems) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ServerItems) Less(i, j int) bool { return a[i].Name < a[j].Name }

// GetServersIndex list all servers
func GetServersIndex(ctx *web.Context, cfg types.Config, db *models.DB, sess session.Store) {
	ctx.Data["NavClass_Servers"] = "active"
	ctx.Data["SideClass_Index"] = "active"

	ss := []models.Server{}
	db.Order("name ASC").Find(&ss)

	items := []ServerItem{}

	for _, s := range ss {
		items = append(items, ServerItem{
			ID:        s.ID,
			Name:      s.Name,
			Address:   s.Address,
			CreatedAt: TimeAgo(&s.CreatedAt),
			UpdatedAt: TimeAgo(&s.UpdatedAt),
			IsAuto:    utils.ToBool(s.IsAuto),
			UsedAt:    TimeAgo(s.UsedAt),
		})
	}

	sort.Sort(ServerItems(items))
	ctx.Data["Servers"] = items

	ctx.HTML(200, "servers/index")
}

// GetServersNew get servers new
func GetServersNew(ctx *web.Context, sess session.Store) {
	ctx.Data["NavClass_Servers"] = "active"
	ctx.Data["Server"] = map[string]string{
		"Name":    ctx.Query("name"),
		"Address": ctx.Query("address"),
	}
	ctx.HTML(200, "servers/new")
}

// ServerCreateForm server add form
type ServerCreateForm struct {
	Name    string `form:"name"`
	Address string `form:"address"`
}

// Validate validate
func (f ServerCreateForm) Validate() (ServerCreateForm, error) {
	f.Name = strings.TrimSpace(f.Name)
	f.Address = strings.TrimSpace(f.Address)

	if len(f.Address) == 0 {
		return f, errors.New("服务器地址不能为空")
	}

	if !models.NamePattern.MatchString(f.Name) {
		return f, errors.New("服务器名称不符合规则")
	}

	if len(strings.Split(f.Address, ":")) < 2 {
		f.Address = fmt.Sprintf("%s:22", f.Address)
	}
	return f, nil
}

// PostServerCreate post server add
func PostServerCreate(ctx *web.Context, f ServerCreateForm, fl *session.Flash, db *models.DB, sess session.Store) {
	var err error
	if f, err = f.Validate(); err != nil {
		fl.Error(err.Error())
		ctx.Redirect(AppendQuery(ctx.URLFor("new-server"), "name", f.Name, "address", f.Address))
		return
	}
	s := models.Server{
		Name:    f.Name,
		Address: f.Address,
	}
	err = db.Create(&s).Error
	if err == nil {
		fl.Success(fmt.Sprintf("添加服务器 %s 成功", f.Name))
	} else {
		fl.Error(err.Error())
	}
	ctx.Redirect(ctx.URLFor("new-server"))
}

// GetServerEdit get server edit
func GetServerEdit(ctx *web.Context, db *models.DB, fl *session.Flash) {
	ctx.Data["NavClass_Servers"] = "active"
	s := models.Server{}
	if db.First(&s, ctx.Params(":id")).Error != nil {
		fl.Error("没有找到目标服务器")
		ctx.Redirect(ctx.URLFor("servers"))
		return
	}
	if utils.ToBool(s.IsAuto) {
		fl.Error("无法编辑自动管理的服务器")
		ctx.Redirect(ctx.URLFor("servers"))
	}
	ctx.Data["Server"] = s
	ctx.HTML(http.StatusOK, "servers/edit")
}

// PostServerUpdate post server update
func PostServerUpdate(ctx *web.Context, f ServerCreateForm, fl *session.Flash, db *models.DB, sess session.Store) {
	id := ctx.Params(":id")
	var err error
	if f, err = f.Validate(); err != nil {
		fl.Error(err.Error())
		ctx.Redirect(ctx.URLFor("edit-server", ":id", id))
		return
	}
	s := models.Server{}
	if err = db.First(&s, id).Error; err != nil || f.Name != s.Name {
		fl.Error("没有找到目标服务器")
		ctx.Redirect(ctx.URLFor("servers"))
		return
	}
	if utils.ToBool(s.IsAuto) {
		fl.Error("无法编辑自动管理的服务器")
		ctx.Redirect(ctx.URLFor("servers"))
	}
	if err = db.Model(&s).Update(map[string]interface{}{"address": f.Address}).Error; err != nil {
		fl.Error(err.Error())
		ctx.Redirect(ctx.URLFor("edit-server", ":id", id))
		return
	}
	fl.Success(fmt.Sprintf("服务器 %s 更新成功", f.Name))
	ctx.Redirect(ctx.URLFor("servers"))
}

// PostServerDestroy post server destroy
func PostServerDestroy(ctx *web.Context, db *models.DB) {
	defer ctx.Redirect(ctx.URLFor("servers"))
	db.Delete(&models.Server{}, "id = ? AND is_auto = ?", ctx.Params(":id"), utils.False)
}

// GetMasterKey get master key
func GetMasterKey(ctx *web.Context, cfg types.Config) {
	ctx.Data["NavClass_Servers"] = "active"
	ctx.Data["SideClass_MasterKey"] = "active"
	ctx.Data["MasterPublicKey"] = GenerateClientAuthorizedKey(cfg)
	ctx.HTML(200, "servers/master-key")
}
