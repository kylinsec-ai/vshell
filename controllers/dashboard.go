// Package controllers implements dashboard-related HTTP handlers.
// Response fields are determined by the current engine implementation and should
// be covered by tests rather than assumed to match another binary exactly.
package controllers

// DashboardController handles dashboard requests.
type DashboardController struct {
	ApiBaseController
}

// Info returns the summary produced by the engine's current app-info implementation.
func (c *DashboardController) Info() {
	info := engineGetAppInfo()
	c.JsonOkResult(info)
}
