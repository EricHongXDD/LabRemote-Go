package sshclient

import (
	"errors"
	"os"
	"strings"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"golang.org/x/crypto/ssh"
)

const maximumPrivateKeyBytes = 1024 * 1024

// LoadPrivateKeyFile 只在内存中解析用户选择的私钥，不会复制或修改原文件。
func LoadPrivateKeyFile(path string, passphrase []byte) (ssh.Signer, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, model.NewAppError("SSH_PRIVATE_KEY_NOT_FOUND", "未选择 SSH 私钥文件", "ssh_auth", false)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, model.NewAppError("SSH_PRIVATE_KEY_NOT_FOUND", "无法读取 SSH 私钥文件", "ssh_auth", false)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumPrivateKeyBytes {
		return nil, false, model.NewAppError("SSH_PRIVATE_KEY_INVALID", "SSH 私钥必须是小于 1 MiB 的普通文件", "ssh_auth", false)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, model.NewAppError("SSH_PRIVATE_KEY_NOT_FOUND", "无法读取 SSH 私钥文件", "ssh_auth", false)
	}
	defer secrets.Zero(content)

	signer, err := ssh.ParsePrivateKey(content)
	if err == nil {
		return signer, false, nil
	}
	var missingPassphrase *ssh.PassphraseMissingError
	if !errors.As(err, &missingPassphrase) {
		return nil, false, model.NewAppError("SSH_PRIVATE_KEY_INVALID", "SSH 私钥格式无效或不受支持", "ssh_auth", false).WithDetails(map[string]any{"reason": err.Error()})
	}
	if len(passphrase) == 0 {
		return nil, true, model.NewAppError("SSH_KEY_PASSPHRASE_REQUIRED", "SSH 私钥已加密，请填写私钥口令", "ssh_auth", false)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(content, passphrase)
	if err != nil {
		return nil, true, model.NewAppError("SSH_KEY_PASSPHRASE_INVALID", "SSH 私钥口令错误或私钥无法解密", "ssh_auth", false)
	}
	return signer, true, nil
}
