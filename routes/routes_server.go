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
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"ireul.com/bunker/models"
	"ireul.com/bunker/types"
	"ireul.com/web"
	"ireul.com/web/session"
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
	GroupName string
	Address   string
	CreatedAt string
	UpdatedAt string
}

// ServerItems slice of server item
type ServerItems []ServerItem

func (a ServerItems) Len() int           { return len(a) }
func (a ServerItems) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ServerItems) Less(i, j int) bool { return a[i].GroupName < a[j].GroupName }

// GetServers list all servers
func GetServers(ctx *web.Context, cfg types.Config, db *models.DB, sess session.Store) {
	ctx.Data["NamePattern"] = models.NamePattern.String()
	ctx.Data["NavClass_Servers"] = "active"
	ctx.Data["ClientPublicKey"] = GenerateClientAuthorizedKey(cfg)
	ctx.Data["CurrentGroupName"] = sess.Get("CurrentGroupName")
	ctx.Data["CurrentServerName"] = sess.Get("CurrentServerName")
	ctx.Data["CurrentServerAddress"] = sess.Get("CurrentServerAddress")

	ss := []models.Server{}
	db.Find(&ss)

	items := []ServerItem{}

	for _, s := range ss {
		items = append(items, ServerItem{
			ID:        s.ID,
			Name:      s.Name,
			GroupName: s.GroupName,
			Address:   s.Address,
			CreatedAt: TimeAgo(&s.CreatedAt),
			UpdatedAt: TimeAgo(&s.UpdatedAt),
		})
	}

	sort.Sort(ServerItems(items))
	ctx.Data["Servers"] = items

	ctx.HTML(200, "servers")
}

// ServerAddForm server add form
type ServerAddForm struct {
	Name      string `form:"name"`
	GroupName string `form:"group_name"`
	Address   string `form:"address"`
}

// Validate validate
func (f ServerAddForm) Validate() (ServerAddForm, error) {
	if !models.NamePattern.MatchString(f.Name) {
		return f, errors.New("服务器名称不符合规则")
	}
	if !models.NamePattern.MatchString(f.GroupName) {
		return f, errors.New("分组名称不符合规则")
	}
	if len(strings.Split(f.Address, ":")) != 2 {
		f.Address = fmt.Sprintf("%s:22", f.Address)
	}
	return f, nil
}

// PostServerAdd post server add
func PostServerAdd(ctx *web.Context, f ServerAddForm, fl *session.Flash, db *models.DB, sess session.Store) {
	defer ctx.Redirect("/servers")
	var err error
	if f, err = f.Validate(); err != nil {
		fl.Error(err.Error())
		return
	}
	sess.Set("CurrentGroupName", f.GroupName)
	sess.Set("CurrentServerName", f.Name)
	sess.Set("CurrentServerAddress", f.Address)
	s := models.Server{}
	err = db.Assign(map[string]interface{}{
		"group_name": f.GroupName,
		"address":    f.Address,
	}).FirstOrCreate(&s, map[string]interface{}{
		"name": f.Name,
	}).Error
	if err == nil {
		fl.Success(fmt.Sprintf("新建/更新 %s 成功", f.Name))
	}
}
