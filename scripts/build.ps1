$ErrorActionPreference = 'Stop'

# 统一使用 UTF-8 输出，避免中文构建信息乱码。
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$projectRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $projectRoot '.tools'
$env:GOPATH = Join-Path $toolRoot 'gopath'
$env:GOMODCACHE = Join-Path $toolRoot 'gomodcache'
$env:GOCACHE = Join-Path $toolRoot 'gocache'
$env:npm_config_cache = Join-Path $toolRoot 'npm-cache'

$wails = Join-Path $env:GOPATH 'bin\wails.exe'
if (-not (Test-Path -LiteralPath $wails)) {
    go install github.com/wailsapp/wails/v2/cmd/wails@v2.13.0
    if ($LASTEXITCODE -ne 0) {
        throw "Wails CLI 安装失败，退出码：$LASTEXITCODE"
    }
}

$localNSIS = Join-Path $toolRoot 'nsis-portable\nsis-3.12'
if (Test-Path -LiteralPath (Join-Path $localNSIS 'makensis.exe')) {
    $env:Path = "$localNSIS;$env:Path"
}
if (-not (Get-Command makensis.exe -ErrorAction SilentlyContinue)) {
    throw '未找到 NSIS 3.12 makensis.exe。请安装 NSIS，或将官方便携包解压到 .tools\nsis-portable\nsis-3.12。'
}

Set-Location -LiteralPath (Join-Path $projectRoot 'frontend')
npm.cmd ci
if ($LASTEXITCODE -ne 0) {
    throw "前端依赖安装失败，退出码：$LASTEXITCODE"
}
npm.cmd test
if ($LASTEXITCODE -ne 0) {
    throw "前端测试失败，退出码：$LASTEXITCODE"
}
npm.cmd run build
if ($LASTEXITCODE -ne 0) {
    throw "前端构建失败，退出码：$LASTEXITCODE"
}

Set-Location -LiteralPath $projectRoot
go test ./...
if ($LASTEXITCODE -ne 0) {
    throw "Go 测试失败，退出码：$LASTEXITCODE"
}

& $wails build -clean -platform windows/amd64 -webview2 embed -nsis -installscope user -trimpath -nocolour
if ($LASTEXITCODE -ne 0) {
    throw "Wails 构建失败，退出码：$LASTEXITCODE"
}
