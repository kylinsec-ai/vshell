// Package controllers implements the HTTP handlers for the web management interface.
//
// Some names and routes were reconstructed from available frontend and binary-analysis
// artifacts. Those artifacts are evidence for individual symbols or paths, not proof of
// complete runtime parity. Authentication and authorization must be reviewed per handler.
package controllers

import (
	"encoding/json"
	"strconv"
	"strings"

	beego "github.com/beego/beego/v2/server/web"
)

// ApiBaseController 是所有控制器的基类，对应原版二进制中的
// nTApp6jPzv.(*ApiBaseController)（funcnametab 可验证，方法地址见 .re/REAL_APP_INVENTORY.txt）。
//
// 真实方法（反编译地址）：
//
//	Prepare       0x18d7ae0   token 校验
//	JsonGet       0x18d7de0   读取任意参数
//	JsonGetInt    0x18d7f40   读取 int 参数
//	JsonGetStr    0x18d80a0   读取 string 参数
//	JsonGetIntList 0x18d8200  读取 int 列表参数
//	JsonGetStrList 0x18d84a0  读取 string 列表参数
//	JsonGetBool   0x18d8780   读取 bool 参数
//	JsonOkMessage 0x18d88e0   成功消息响应 {"code":0,"message":"ok","type":msg}
//	JsonOkResult  0x18d8b00   成功数据响应 {"code":0,"message":"ok","type":"success","result":data}
//	JsonErr       0x18d8d80   错误响应     {"code":-1,"message":msg,"type":"error","result":null}
//	JsonTimeout   0x18d9000   超时响应     {"code":-1,"result":null}
//	GetIntNoErr   0x18d9200
//	GetBoolNoErr  0x18d92c0
type ApiBaseController struct {
	beego.Controller
}

// Prepare 请求预处理（反编译 0x18d7ae0，逐分支还原）：
//  1. 路径为 /api/login 或 /api/logout（解密字符串）→ 放行；
//  2. 读取 Token 头（FUN_008a8dc0），为空再读 token 参数（FUN_018d9180）；
//  3. 两者皆空 → 输出 HTTP 401（Output status 0x191）后返回；
//  4. 会话校验失败 → JsonTimeout（{"code":-1,"result":null}）；
//  5. 会话无效 → 401。
//
// 拒绝分支直接写响应头，而不用 StopRun：beego 的 StopRun 是 panic(ErrAbort)，
// 而默认 recover（defaultRecoverPanic）对 ErrAbort 直接 return、不落状态码，
// 于是未授权请求会以 200 返回。写头会把 beego 的 Response.Started 置真，
// beego 随即跳过控制器方法体与 AutoRender——这正是拒绝所需的语义。
//
// Rejections write the header directly rather than calling StopRun: beego
// implements StopRun as panic(ErrAbort), and its default recover returns for
// ErrAbort without emitting the status code, so an unauthenticated request
// would come back 200. Writing the header sets beego's Response.Started, which
// makes beego skip both the action method and AutoRender.
func (c *ApiBaseController) Prepare() {
	path := c.Ctx.Input.URL()
	if path == "/api/login" || path == "/api/logout" {
		return
	}
	token := c.Ctx.Input.Header("Token")
	if token == "" {
		token = c.GetString("token")
	}
	if token == "" {
		c.denyUnauthorized()
		return
	}
	if !CheckToken(token) {
		c.JsonTimeout()
		return
	}
	// 会话校验（原版 FUN_01737500 / FUN_00c8dc20 会话存储检查）
	if !engineCheckSession(token) {
		c.denyUnauthorized()
		return
	}
}

// denyUnauthorized 落 401 并终止本次请求的处理。
// denyUnauthorized emits 401 and stops this request from reaching an action.
func (c *ApiBaseController) denyUnauthorized() {
	c.Ctx.Output.SetStatus(401)
	c.Ctx.ResponseWriter.WriteHeader(401)
}

// JsonGet 读取任意参数值（GET 查询串 / 表单 / JSON 请求体，与 beego 输入解析一致）。
func (c *ApiBaseController) JsonGet(key string) interface{} {
	vals, _ := c.Input()
	if v := vals.Get(key); v != "" {
		return v
	}
	return c.jsonBodyValue(key)
}

// jsonBodyValue 从 JSON 请求体中读取键值（前端 axios 以 JSON 提交参数）。
func (c *ApiBaseController) jsonBodyValue(key string) string {
	body := c.Ctx.Input.RequestBody
	if len(body) == 0 {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "1"
		}
		return "0"
	default:
		if v == nil {
			return ""
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// JsonGetInt 读取 int 参数（反编译：FUN_018d7f40 经 beego Input 取字符串后转 int）。
func (c *ApiBaseController) JsonGetInt(key string) int {
	v, err := c.GetInt(key, 0)
	if err != nil || v == 0 {
		if s := c.jsonBodyValue(key); s != "" {
			n, err := strconv.Atoi(s)
			if err == nil {
				return n
			}
		}
	}
	return v
}

// JsonGetStr 读取 string 参数（反编译：FUN_018d80a0）。
func (c *ApiBaseController) JsonGetStr(key string) string {
	s := c.GetString(key)
	if s == "" {
		s = c.jsonBodyValue(key)
	}
	return s
}

// JsonGetBool 读取 bool 参数（反编译：FUN_018d8780）。
func (c *ApiBaseController) JsonGetBool(key string) bool {
	v, err := c.GetBool(key, false)
	if err != nil {
		return false
	}
	return v
}

// JsonGetIntList 读取 int 列表参数（反编译：FUN_018d8200；逗号分隔或 JSON 数组）。
func (c *ApiBaseController) JsonGetIntList(key string) []int {
	s := c.GetString(key)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// JsonGetStrList 读取 string 列表参数（反编译：FUN_018d84a0；逗号分隔或 JSON 数组）。
func (c *ApiBaseController) JsonGetStrList(key string) []string {
	s := c.GetString(key)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// JsonOkMessage 成功消息响应：{"code":0,"message":"ok","type":<msg>}
// 反编译（0x18d88e0）键集合：code / message / type。
func (c *ApiBaseController) JsonOkMessage(msg string) {
	c.Data["json"] = map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    msg,
	}
	c.ServeJSON()
}

// JsonOkResult 成功数据响应：{"code":0,"message":"ok","type":"success","result":<data>}
// 反编译（0x18d8b00）键集合：code / result / message / type；字符串值 "ok"、"success"
// 已在二进制中解析确认（0x1bd68a2="ok"，0x1bdbe27="success"）。
func (c *ApiBaseController) JsonOkResult(result interface{}) {
	c.Data["json"] = map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  result,
	}
	c.ServeJSON()
}

// JsonErr 错误响应：{"code":-1,"message":<msg>,"type":"error","result":null}
// 反编译（0x18d8d80）键集合：code / result / message / type；
// code 值 -1（0xffffffffffffffff）、type 值 "error"（0x1bd8abe）已在二进制中解析确认。
func (c *ApiBaseController) JsonErr(msg string) {
	c.Data["json"] = map[string]interface{}{
		"code":    -1,
		"message": msg,
		"type":    "error",
		"result":  nil,
	}
	c.ServeJSON()
}

// JsonTimeout 超时/未授权响应：{"code":-1,"result":null}
// 反编译（0x18d9000）键集合：code / result。
// 显式写出 401：原版通过 Output status 触发该状态码，而复刻端若只依赖 beego
// 的 AutoRender 分支，响应会落在 200 上——401 必须自己落到响应里。
func (c *ApiBaseController) JsonTimeout() {
	c.Ctx.Output.SetStatus(401)
	c.Data["json"] = map[string]interface{}{
		"code":   -1,
		"result": nil,
	}
	c.ServeJSON()
	c.Ctx.ResponseWriter.WriteHeader(401)
}

// GetIntNoErr 读取 int 参数（忽略错误，0x18d9200）。
func (c *ApiBaseController) GetIntNoErr(key string) int {
	v, _ := c.GetInt(key)
	return v
}

// GetBoolNoErr 读取 bool 参数（忽略错误，0x18d92c0）。
func (c *ApiBaseController) GetBoolNoErr(key string) bool {
	v, _ := c.GetBool(key)
	return v
}
