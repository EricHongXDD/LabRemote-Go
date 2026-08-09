package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

const (
	connectionBundleType             = "labremote-connection-bundle"
	connectionBundleVersion          = 1
	connectionBundleAAD              = "LabRemote connection bundle v1"
	connectionBundleSaltSize         = 16
	connectionBundleArgonTime        = 3
	connectionBundleArgonMemoryKiB   = 64 * 1024
	connectionBundleArgonParallelism = 4
	connectionBundleKeySize          = 32
	connectionBundleMaxProfiles      = 256
	connectionBundleMaxPrivateKey    = 4 * 1024 * 1024
	connectionBundleMaxPlaintext     = 46 * 1024 * 1024

	// MaxConnectionBundleFileSize 限制导入文件，避免异常文件占用过多内存。
	MaxConnectionBundleFileSize = 64 * 1024 * 1024
)

type connectionBundleKDF struct {
	Name        string `json:"name"`
	Salt        []byte `json:"salt"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

type connectionBundleCipher struct {
	Name  string `json:"name"`
	Nonce []byte `json:"nonce"`
}

type encryptedConnectionBundle struct {
	Type       string                 `json:"type"`
	Version    int                    `json:"version"`
	KDF        connectionBundleKDF    `json:"kdf"`
	Cipher     connectionBundleCipher `json:"cipher"`
	Ciphertext []byte                 `json:"ciphertext"`
}

type connectionBundlePayload struct {
	ExportedAt time.Time                 `json:"exported_at"`
	Profiles   []connectionBundleProfile `json:"profiles"`
}

type connectionBundleProfile struct {
	Profile                 model.ConnectionProfile  `json:"profile"`
	VPNPreSharedKey         []byte                   `json:"vpn_pre_shared_key,omitempty"`
	VPNPassword             []byte                   `json:"vpn_password,omitempty"`
	SSHPassword             []byte                   `json:"ssh_password,omitempty"`
	SSHPrivateKey           []byte                   `json:"ssh_private_key,omitempty"`
	SSHPrivateKeyName       string                   `json:"ssh_private_key_name,omitempty"`
	SSHPrivateKeyPassphrase []byte                   `json:"ssh_private_key_passphrase,omitempty"`
	KnownHost               *sshclient.HostKeyRecord `json:"known_host,omitempty"`
}

type ImportConnectionsResult struct {
	Imported int      `json:"imported"`
	Renamed  int      `json:"renamed"`
	Names    []string `json:"names"`
}

// ExportConnectionBundle 收集连接配置及其独立凭据，并生成经过密码认证加密的可移植连接包。
func (s *Service) ExportConnectionBundle(ctx context.Context, profileIDs []string, password string) ([]byte, int, error) {
	passwordBytes, err := validateBundlePassword(password)
	if err != nil {
		return nil, 0, err
	}
	defer secrets.Zero(passwordBytes)
	if len(profileIDs) == 0 {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_EMPTY", "请至少选择一个要导出的连接", "connection_export", false)
	}
	if len(profileIDs) > connectionBundleMaxProfiles {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_TOO_LARGE", "单个连接包最多包含 256 个连接", "connection_export", false)
	}

	seen := make(map[string]struct{}, len(profileIDs))
	payload := connectionBundlePayload{ExportedAt: time.Now().UTC(), Profiles: make([]connectionBundleProfile, 0, len(profileIDs))}
	defer zeroConnectionBundlePayload(&payload)
	for _, profileID := range profileIDs {
		profileID = strings.TrimSpace(profileID)
		if profileID == "" {
			return nil, 0, model.NewAppError("CONNECTION_EXPORT_INVALID", "导出列表中包含无效连接", "connection_export", false)
		}
		if _, ok := seen[profileID]; ok {
			continue
		}
		seen[profileID] = struct{}{}
		value, getErr := s.profiles.Get(ctx, profileID)
		if getErr != nil {
			return nil, 0, getErr
		}
		item, collectErr := s.collectBundleProfile(ctx, value)
		if collectErr != nil {
			return nil, 0, collectErr
		}
		payload.Profiles = append(payload.Profiles, item)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_FAILED", "无法生成连接导出数据", "connection_export", true)
	}
	defer secrets.Zero(plaintext)
	if len(plaintext) > connectionBundleMaxPlaintext {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_TOO_LARGE", "所选连接及私钥生成的连接包超过 64 MiB 限制", "connection_export", false)
	}
	encrypted, err := encryptConnectionBundle(plaintext, passwordBytes)
	if err != nil {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_FAILED", "无法加密连接导出文件", "connection_export", true)
	}
	if len(encrypted) > MaxConnectionBundleFileSize {
		return nil, 0, model.NewAppError("CONNECTION_EXPORT_TOO_LARGE", "加密连接包超过 64 MiB 限制", "connection_export", false)
	}
	return encrypted, len(payload.Profiles), nil
}

func (s *Service) collectBundleProfile(ctx context.Context, value model.ConnectionProfile) (result connectionBundleProfile, returnErr error) {
	item := connectionBundleProfile{Profile: value}
	defer func() {
		if returnErr != nil {
			zeroConnectionBundleProfile(&item)
		}
	}()
	var err error
	if value.UsesIsolatedTunnel() {
		item.VPNPassword, err = s.requiredBundleSecret(ctx, model.VPNPasswordKey(value.ID), value.DisplayName, "隔离隧道密码")
		if err != nil {
			return connectionBundleProfile{}, err
		}
		item.VPNPreSharedKey, err = s.optionalBundleSecret(ctx, model.VPNPSKKey(value.ID))
		if err != nil {
			return connectionBundleProfile{}, err
		}
	}
	if value.SSH.EffectiveAuthMethod() == model.SSHAuthPassword {
		item.SSHPassword, err = s.requiredBundleSecret(ctx, model.SSHPasswordKey(value.ID), value.DisplayName, "SSH 密码")
		if err != nil {
			return connectionBundleProfile{}, err
		}
	} else {
		pathBytes, getErr := s.requiredBundleSecret(ctx, model.SSHPrivateKeyPathKey(value.ID), value.DisplayName, "SSH 私钥路径")
		if getErr != nil {
			return connectionBundleProfile{}, getErr
		}
		defer secrets.Zero(pathBytes)
		item.SSHPrivateKeyPassphrase, err = s.optionalBundleSecret(ctx, model.SSHPrivateKeyPassphraseKey(value.ID))
		if err != nil {
			return connectionBundleProfile{}, err
		}
		item.SSHPrivateKey, err = readBundlePrivateKey(string(pathBytes))
		if err != nil {
			return connectionBundleProfile{}, model.NewAppError("CONNECTION_EXPORT_PRIVATE_KEY_FAILED", fmt.Sprintf("无法读取连接“%s”的 SSH 私钥", value.DisplayName), "connection_export", false).WithDetails(map[string]any{"reason": err.Error()})
		}
		if _, _, parseErr := parseBundlePrivateKey(item.SSHPrivateKey, item.SSHPrivateKeyPassphrase); parseErr != nil {
			return connectionBundleProfile{}, model.NewAppError("CONNECTION_EXPORT_PRIVATE_KEY_FAILED", fmt.Sprintf("连接“%s”的 SSH 私钥或口令无效", value.DisplayName), "connection_export", false)
		}
		item.SSHPrivateKeyName = filepath.Base(string(pathBytes))
	}
	if record, ok, lookupErr := s.knownHosts.Lookup(value.ID); lookupErr != nil {
		return connectionBundleProfile{}, lookupErr
	} else if ok {
		recordCopy := record
		item.KnownHost = &recordCopy
	}
	return item, nil
}

func (s *Service) requiredBundleSecret(ctx context.Context, key, profileName, label string) ([]byte, error) {
	value, err := s.secrets.Get(ctx, key)
	if errors.Is(err, secrets.ErrNotFound) {
		secrets.Zero(value)
		return nil, model.NewAppError("CONNECTION_EXPORT_CREDENTIAL_MISSING", fmt.Sprintf("连接“%s”缺少已保存的%s，请先编辑并保存凭据", profileName, label), "connection_export", false)
	}
	if err != nil {
		secrets.Zero(value)
		return nil, model.NewAppError("CONNECTION_EXPORT_CREDENTIAL_FAILED", fmt.Sprintf("无法读取连接“%s”的%s", profileName, label), "connection_export", true)
	}
	if len(value) == 0 {
		return nil, model.NewAppError("CONNECTION_EXPORT_CREDENTIAL_MISSING", fmt.Sprintf("连接“%s”缺少已保存的%s，请先编辑并保存凭据", profileName, label), "connection_export", false)
	}
	return value, nil
}

func (s *Service) optionalBundleSecret(ctx context.Context, key string) ([]byte, error) {
	value, err := s.secrets.Get(ctx, key)
	if errors.Is(err, secrets.ErrNotFound) {
		secrets.Zero(value)
		return nil, nil
	}
	if err != nil {
		secrets.Zero(value)
		return nil, model.NewAppError("CONNECTION_EXPORT_CREDENTIAL_FAILED", "无法读取可选连接凭据", "connection_export", true)
	}
	return value, nil
}

// ImportConnectionBundle 解密连接包，并以新 ID 导入全部连接，避免覆盖本机已有配置。
func (s *Service) ImportConnectionBundle(ctx context.Context, data []byte, password, privateKeyDirectory string) (result ImportConnectionsResult, returnErr error) {
	passwordBytes, err := validateBundlePassword(password)
	if err != nil {
		return result, err
	}
	defer secrets.Zero(passwordBytes)
	if len(data) == 0 || len(data) > MaxConnectionBundleFileSize {
		return result, model.NewAppError("CONNECTION_BUNDLE_INVALID", "连接导出文件为空或超过 64 MiB", "connection_import", false)
	}
	payload, err := decryptConnectionBundle(data, passwordBytes)
	if err != nil {
		return result, err
	}
	defer zeroConnectionBundlePayload(&payload)
	if len(payload.Profiles) == 0 || len(payload.Profiles) > connectionBundleMaxProfiles {
		return result, model.NewAppError("CONNECTION_BUNDLE_INVALID", "连接导出文件中的连接数量无效", "connection_import", false)
	}
	privateKeyDirectory = strings.TrimSpace(privateKeyDirectory)
	if privateKeyDirectory == "" {
		return result, model.NewAppError("CONNECTION_IMPORT_FAILED", "无法定位导入私钥的保存目录", "connection_import", true)
	}

	existing, err := s.profiles.List(ctx)
	if err != nil {
		return result, err
	}
	usedNames := make(map[string]struct{}, len(existing)+len(payload.Profiles))
	for _, value := range existing {
		usedNames[strings.ToLower(strings.TrimSpace(value.DisplayName))] = struct{}{}
	}
	type importPlan struct {
		bundle           *connectionBundleProfile
		profile          model.ConnectionProfile
		privateKeyPath   string
		privateEncrypted bool
	}
	plans := make([]importPlan, 0, len(payload.Profiles))
	now := time.Now()
	for index := range payload.Profiles {
		item := &payload.Profiles[index]
		value := item.Profile
		originalName := strings.TrimSpace(value.DisplayName)
		value.DisplayName = uniqueImportedProfileName(originalName, usedNames)
		if value.DisplayName != originalName {
			result.Renamed++
		}
		value.ID = uuid.NewString()
		value.CreatedAt = now
		value.UpdatedAt = now
		value.ConnectionMode = value.EffectiveConnectionMode()
		value.SSH.AuthMethod = value.SSH.EffectiveAuthMethod()
		if value.UsesIsolatedTunnel() {
			value.VPN.ConnectionName = value.DisplayName
			value.VPN.CredentialRef = model.VPNPasswordKey(value.ID)
			if len(item.VPNPassword) == 0 {
				return result, invalidBundleCredential(value.DisplayName, "隔离隧道密码")
			}
		} else {
			value.VPN.CredentialRef = ""
		}
		plan := importPlan{bundle: item, profile: value}
		if value.SSH.EffectiveAuthMethod() == model.SSHAuthPrivateKey {
			if len(item.SSHPrivateKey) == 0 {
				return result, invalidBundleCredential(value.DisplayName, "SSH 私钥")
			}
			_, encrypted, parseErr := parseBundlePrivateKey(item.SSHPrivateKey, item.SSHPrivateKeyPassphrase)
			if parseErr != nil {
				return result, model.NewAppError("CONNECTION_BUNDLE_INVALID", fmt.Sprintf("连接“%s”的 SSH 私钥或口令无效", value.DisplayName), "connection_import", false)
			}
			plan.privateEncrypted = encrypted
			plan.privateKeyPath = filepath.Join(privateKeyDirectory, value.ID+"-"+safePrivateKeyName(item.SSHPrivateKeyName))
			value.SSH.CredentialRef = model.SSHPrivateKeyPathKey(value.ID)
		} else {
			if len(item.SSHPassword) == 0 {
				return result, invalidBundleCredential(value.DisplayName, "SSH 密码")
			}
			value.SSH.CredentialRef = model.SSHPasswordKey(value.ID)
		}
		if err := value.Validate(); err != nil {
			return result, model.NewAppError("CONNECTION_BUNDLE_INVALID", fmt.Sprintf("连接“%s”的配置无效", value.DisplayName), "connection_import", false).WithDetails(map[string]any{"reason": err.Error()})
		}
		plan.profile = value
		plans = append(plans, plan)
	}

	// 所有导入对象都使用新 ID，因此可以在失败时安全回滚，不会删除原有数据。
	rollback := func() {
		for _, plan := range plans {
			_ = s.profiles.Delete(context.Background(), plan.profile.ID)
			_ = s.knownHosts.Remove(plan.profile.ID)
			for _, key := range profileSecretKeys(plan.profile.ID) {
				_ = s.secrets.Delete(context.Background(), key)
			}
			if plan.privateKeyPath != "" {
				_ = os.Remove(plan.privateKeyPath)
			}
		}
	}
	committed := false
	defer func() {
		if !committed {
			rollback()
		}
	}()

	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		item := plan.bundle
		if plan.privateKeyPath != "" {
			if err := writeImportedPrivateKey(plan.privateKeyPath, item.SSHPrivateKey); err != nil {
				return result, model.NewAppError("CONNECTION_IMPORT_PRIVATE_KEY_FAILED", fmt.Sprintf("无法保存连接“%s”的 SSH 私钥", plan.profile.DisplayName), "connection_import", true).WithDetails(map[string]any{"reason": err.Error()})
			}
			if err := s.secrets.Put(ctx, model.SSHPrivateKeyPathKey(plan.profile.ID), []byte(plan.privateKeyPath)); err != nil {
				return result, importSecretStoreError()
			}
			if plan.privateEncrypted {
				if err := s.secrets.Put(ctx, model.SSHPrivateKeyPassphraseKey(plan.profile.ID), item.SSHPrivateKeyPassphrase); err != nil {
					return result, importSecretStoreError()
				}
			}
		} else if err := s.secrets.Put(ctx, model.SSHPasswordKey(plan.profile.ID), item.SSHPassword); err != nil {
			return result, importSecretStoreError()
		}
		if plan.profile.UsesIsolatedTunnel() {
			if err := s.secrets.Put(ctx, model.VPNPasswordKey(plan.profile.ID), item.VPNPassword); err != nil {
				return result, importSecretStoreError()
			}
			if len(item.VPNPreSharedKey) > 0 {
				if err := s.secrets.Put(ctx, model.VPNPSKKey(plan.profile.ID), item.VPNPreSharedKey); err != nil {
					return result, importSecretStoreError()
				}
			}
		}
		if err := s.profiles.Upsert(ctx, plan.profile); err != nil {
			return result, err
		}
		if item.KnownHost != nil {
			record := *item.KnownHost
			record.ProfileID = plan.profile.ID
			if err := s.knownHosts.Store(record); err != nil {
				return result, err
			}
		}
		result.Names = append(result.Names, plan.profile.DisplayName)
	}
	result.Imported = len(plans)
	committed = true
	return result, nil
}

func validateBundlePassword(password string) ([]byte, error) {
	passwordBytes := []byte(password)
	if utf8.RuneCountInString(password) < 8 || len(passwordBytes) > 1024 {
		secrets.Zero(passwordBytes)
		return nil, model.NewAppError("CONNECTION_BUNDLE_PASSWORD_INVALID", "导出密码至少需要 8 个字符，且不能超过 1024 字节", "connection_bundle", false)
	}
	return passwordBytes, nil
}

func encryptConnectionBundle(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, connectionBundleSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, connectionBundleArgonTime, connectionBundleArgonMemoryKiB, connectionBundleArgonParallelism, connectionBundleKeySize)
	defer secrets.Zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	envelope := encryptedConnectionBundle{
		Type:    connectionBundleType,
		Version: connectionBundleVersion,
		KDF: connectionBundleKDF{
			Name: "argon2id", Salt: salt, Time: connectionBundleArgonTime,
			MemoryKiB: connectionBundleArgonMemoryKiB, Parallelism: connectionBundleArgonParallelism,
		},
		Cipher:     connectionBundleCipher{Name: "aes-256-gcm", Nonce: nonce},
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(connectionBundleAAD)),
	}
	return json.MarshalIndent(envelope, "", "  ")
}

func decryptConnectionBundle(data, password []byte) (connectionBundlePayload, error) {
	var envelope encryptedConnectionBundle
	if err := json.Unmarshal(data, &envelope); err != nil {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_INVALID", "无法解析连接导出文件", "connection_import", false)
	}
	if envelope.Type != connectionBundleType || envelope.Version != connectionBundleVersion || envelope.KDF.Name != "argon2id" || envelope.Cipher.Name != "aes-256-gcm" {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_UNSUPPORTED", "连接导出文件格式或版本不受支持", "connection_import", false)
	}
	if len(envelope.KDF.Salt) != connectionBundleSaltSize || envelope.KDF.Time != connectionBundleArgonTime || envelope.KDF.MemoryKiB != connectionBundleArgonMemoryKiB || envelope.KDF.Parallelism != connectionBundleArgonParallelism {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_INVALID", "连接导出文件的密钥派生参数无效", "connection_import", false)
	}
	key := argon2.IDKey(password, envelope.KDF.Salt, envelope.KDF.Time, envelope.KDF.MemoryKiB, envelope.KDF.Parallelism, connectionBundleKeySize)
	defer secrets.Zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_INVALID", "无法初始化连接包解密器", "connection_import", false)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(envelope.Cipher.Nonce) != gcm.NonceSize() {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_INVALID", "连接导出文件的加密参数无效", "connection_import", false)
	}
	plaintext, err := gcm.Open(nil, envelope.Cipher.Nonce, envelope.Ciphertext, []byte(connectionBundleAAD))
	if err != nil {
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_DECRYPT_FAILED", "密码错误，或连接导出文件已损坏", "connection_import", false)
	}
	defer secrets.Zero(plaintext)
	var payload connectionBundlePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		zeroConnectionBundlePayload(&payload)
		return connectionBundlePayload{}, model.NewAppError("CONNECTION_BUNDLE_INVALID", "连接导出文件的加密内容无效", "connection_import", false)
	}
	return payload, nil
}

func readBundlePrivateKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > connectionBundleMaxPrivateKey {
		return nil, fmt.Errorf("私钥文件必须是小于 4 MiB 的普通文件")
	}
	return os.ReadFile(path)
}

func parseBundlePrivateKey(data, passphrase []byte) (ssh.Signer, bool, error) {
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, false, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, false, err
	}
	if len(passphrase) == 0 {
		return nil, true, err
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	return signer, true, err
}

func writeImportedPrivateKey(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "private-key-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func uniqueImportedProfileName(name string, used map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "导入的连接"
	}
	if _, exists := used[strings.ToLower(name)]; !exists {
		used[strings.ToLower(name)] = struct{}{}
		return name
	}
	for index := 1; ; index++ {
		suffix := "（导入）"
		if index > 1 {
			suffix = fmt.Sprintf("（导入 %d）", index)
		}
		candidate := truncateRunes(name, 64-utf8.RuneCountInString(suffix)) + suffix
		key := strings.ToLower(candidate)
		if _, exists := used[key]; !exists {
			used[key] = struct{}{}
			return candidate
		}
	}
}

func truncateRunes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}

func safePrivateKeyName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "ssh-key"
	}
	var builder strings.Builder
	runeCount := 0
	for _, value := range []rune(name) {
		if value < 32 || strings.ContainsRune(`<>:"/\|?*`, value) {
			builder.WriteRune('_')
		} else {
			builder.WriteRune(value)
		}
		runeCount++
		if runeCount >= 80 {
			break
		}
	}
	result := strings.Trim(builder.String(), " .")
	if result == "" {
		return "ssh-key"
	}
	return result
}

func invalidBundleCredential(profileName, label string) error {
	return model.NewAppError("CONNECTION_BUNDLE_INVALID", fmt.Sprintf("连接“%s”缺少%s", profileName, label), "connection_import", false)
}

func importSecretStoreError() error {
	return model.NewAppError("CONNECTION_IMPORT_CREDENTIAL_FAILED", "无法把导入凭据写入系统安全存储，已回滚本次导入", "connection_import", true)
}

func profileSecretKeys(profileID string) []string {
	return []string{
		model.VPNPSKKey(profileID), model.VPNPasswordKey(profileID), model.SSHPasswordKey(profileID),
		model.SSHPrivateKeyPathKey(profileID), model.SSHPrivateKeyPassphraseKey(profileID),
	}
}

func zeroConnectionBundlePayload(payload *connectionBundlePayload) {
	if payload == nil {
		return
	}
	for index := range payload.Profiles {
		zeroConnectionBundleProfile(&payload.Profiles[index])
	}
}

func zeroConnectionBundleProfile(item *connectionBundleProfile) {
	if item == nil {
		return
	}
	secrets.Zero(item.VPNPreSharedKey)
	secrets.Zero(item.VPNPassword)
	secrets.Zero(item.SSHPassword)
	secrets.Zero(item.SSHPrivateKey)
	secrets.Zero(item.SSHPrivateKeyPassphrase)
}
