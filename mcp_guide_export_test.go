package main

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func TestWriteMCPAIGuideWritesExactUTF8Markdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LabRemote-AI-终端操作手册.md")
	first := "# 旧内容\n这部分必须被覆盖。\n"
	if err := writeMCPAIGuide(path, first); err != nil {
		t.Fatal(err)
	}
	expected := "# LabRemote AI 终端操作手册\n\n- 中文：远程终端\n- MCP：`labremote`\n"
	if err := writeMCPAIGuide(path, expected); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Fatal("导出的 Markdown 不是有效 UTF-8")
	}
	if string(data) != expected {
		t.Fatalf("导出内容不一致:\n%s", string(data))
	}
}
