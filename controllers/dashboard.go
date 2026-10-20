// Package controllers — 仪表盘控制器，根据当前逆向证据重建；行为等价性仍需逐项验证。
//
// 真实方法（funcnametab + 反编译地址）：
//
//	Info  0x18dc520   GET /dashboard/info  仪表盘统计信息
package controllers

// DashboardController 仪表盘。
type DashboardController struct {
	ApiBaseController
}

// Info 返回仪表盘统计（GET /dashboard/info）。
// 反编译（0x18dc520）调用 FUN_0171a2e0（GetAppInfo）汇总引擎统计。
func (c *DashboardController) Info() {
	info := engineGetAppInfo()
	c.JsonOkResult(info)
}
