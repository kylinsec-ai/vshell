// Package controllers — 登录控制器，根据当前逆向证据重建；行为等价性仍需逐项验证。
//
// 真实方法（funcnametab + 反编译地址）：
//
//	Login       0x18ed000   POST /login          用户名/密码登录
//	Logout      0x18ed560   POST /logout         注销
//	GetUserInfo 0x18ed5c0   GET  /getUserInfo    当前用户信息
package controllers

// LoginController 处理 Web 面板登录。
type LoginController struct {
	ApiBaseController
}

// Login 登录（POST /login）。
// 反编译（0x18ed000）流程：读取用户名/密码 → FUN_01737740 校验（密码做摘要比对）
// → 成功则生成会话 token（FUN_01746d60 / FUN_017476e0）并返回用户信息；
// 失败响应键为 "Error"（0x1bd8488）。
func (c *LoginController) Login() {
	username := c.JsonGetStr("username")
	password := c.JsonGetStr("password")
	if username == "" || password == "" {
		c.Data["json"] = map[string]interface{}{"Error": "username or password empty"}
		c.ServeJSON()
		return
	}
	token, ok := engineVerifyLogin(username, password)
	if !ok {
		// 真实响应（黑盒验证）：{"code":-1,"message":"Incorrect account or password！","result":null,"type":"error"}
		c.Data["json"] = map[string]interface{}{"Error": "Incorrect account or password！"}
		c.ServeJSON()
		return
	}
	engineSetToken(token)
	// 真实响应（黑盒验证）：{"code":0,"message":"ok","result":{"desc":
	// "manager","realName":"admin","roles":[{"roleName":"Super Admin",
	// "value":"super"}],"token":"<JWT>","userId":"1","username":"admin"},
	// "type":"success"}；JWT payload = {token_type:jwt, user_id:1, role_id:1,
	// username, exp, iat}。
	c.Data["json"] = map[string]interface{}{
		"token": token,
		"userInfo": map[string]interface{}{
			"desc":     "manager",
			"realName": username,
			"roles": []map[string]interface{}{
				{"roleName": "Super Admin", "value": "super"},
			},
			"userId":   "1",
			"username": username,
		},
	}
	c.ServeJSON()
}

// Logout 注销（POST /logout）。
// 反编译（0x18ed560）仅清除会话后返回成功；响应与原版一致：
// {"code":0,"message":"ok","type":"success"}。
func (c *LoginController) Logout() {
	token := c.Ctx.Input.Header("Token")
	if token == "" {
		token = c.GetString("token")
	}
	engineDelToken(token)
	c.JsonOkMessage("success")
}

// GetUserInfo 返回当前登录用户信息（GET /getUserInfo）。
func (c *LoginController) GetUserInfo() {
	c.JsonOkResult(map[string]interface{}{
		"userId":   1,
		"username": "admin",
		"roles":    []string{"admin"},
	})
}
