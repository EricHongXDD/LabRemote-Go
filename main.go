package main

import (
	"context"
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	application, err := NewDesktopApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, "LabRemote 初始化失败:", err)
		os.Exit(1)
	}
	runErr := wails.Run(&options.App{
		Title:            "LabRemote",
		Width:            1280,
		Height:           800,
		MinWidth:         980,
		MinHeight:        620,
		DragAndDrop:      &options.DragAndDrop{EnableFileDrop: true},
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 9, G: 15, B: 27, A: 1},
		OnStartup:        application.startup,
		OnShutdown:       application.shutdown,
		Bind:             []interface{}{application},
	})
	// 兜底执行一次清理；正常关闭时 OnShutdown 已经调用过，shutdownOnce 会避免重复释放。
	application.shutdown(context.Background())
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "LabRemote 运行失败:", runErr)
		os.Exit(1)
	}
}
