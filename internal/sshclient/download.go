package sshclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/google/uuid"
	"github.com/pkg/sftp"
)

type downloadJob struct {
	request  model.DownloadRequest
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	progress model.DownloadProgress
	lastEmit time.Time
}

type downloadEntry struct {
	remotePath   string
	relativePath string
	displayName  string
	size         int64
	modTime      time.Time
	mode         os.FileMode
	isDirectory  bool
}

type downloadPlan struct {
	directories []downloadEntry
	files       []downloadEntry
	totalBytes  int64
}

func (m *Manager) ListRemoteDirectory(ctx context.Context, profileID string, directory string) (model.RemoteDirectory, error) {
	runtime := m.runtime(strings.TrimSpace(profileID))
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		return model.RemoteDirectory{}, model.NewAppError("SSH_SESSION_FAILED", "SSH 客户端未连接", "file_download", true)
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return model.RemoteDirectory{}, model.NewAppError("SFTP_UNAVAILABLE", "远端 SSH 服务未提供 SFTP 子系统", "file_download", false)
	}
	defer sftpClient.Close()
	resolved, info, err := resolveRemoteLocation(ctx, sftpClient, directory)
	if err != nil {
		return model.RemoteDirectory{}, err
	}
	if !info.IsDir() {
		return model.RemoteDirectory{}, model.NewAppError("DOWNLOAD_REMOTE_PATH_FAILED", "远端路径不是可访问的目录", "file_download", false)
	}
	entries, err := sftpClient.ReadDir(resolved)
	if err != nil {
		return model.RemoteDirectory{}, model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", "无法读取远端目录", "file_download", true)
	}
	result := make([]model.RemoteEntry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return model.RemoteDirectory{}, err
		}
		result = append(result, model.RemoteEntry{
			Name: entry.Name(), Path: path.Join(resolved, entry.Name()),
			IsDirectory: entry.IsDir(), IsSymlink: entry.Mode()&os.ModeSymlink != 0,
			Size: entry.Size(), ModTimeMS: entry.ModTime().UnixMilli(),
		})
	}
	sort.SliceStable(result, func(first, second int) bool {
		if result[first].IsDirectory != result[second].IsDirectory {
			return result[first].IsDirectory
		}
		return strings.ToLower(result[first].Name) < strings.ToLower(result[second].Name)
	})
	parent := path.Dir(resolved)
	if resolved == "/" {
		parent = "/"
	}
	return model.RemoteDirectory{Path: resolved, Parent: parent, Entries: result}, nil
}

func (m *Manager) StartDownload(ctx context.Context, request model.DownloadRequest) (model.DownloadProgress, error) {
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	request.LocalDirectory = strings.TrimSpace(request.LocalDirectory)
	if request.ProfileID == "" {
		return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_INVALID", "未选择连接配置", "file_download", false)
	}
	if len(request.RemotePaths) == 0 {
		return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_INVALID", "请至少选择一个远端文件或文件夹", "file_download", false)
	}
	localRoot, err := filepath.Abs(request.LocalDirectory)
	if err != nil {
		return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", "无法解析本地目标目录", "file_download", false)
	}
	localInfo, err := os.Stat(localRoot)
	if err != nil || !localInfo.IsDir() {
		return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", "本地目标路径不是可访问的目录", "file_download", false)
	}
	request.LocalDirectory = filepath.Clean(localRoot)
	runtime := m.runtime(request.ProfileID)
	runtime.mu.Lock()
	connected := runtime.client != nil
	runtime.mu.Unlock()
	if !connected {
		return model.DownloadProgress{}, model.NewAppError("SSH_SESSION_FAILED", "SSH 客户端未连接", "file_download", true)
	}

	m.downloadMu.Lock()
	for _, existing := range m.downloads {
		existing.mu.Lock()
		active := existing.progress.ProfileID == request.ProfileID && downloadStateActive(existing.progress.State)
		existing.mu.Unlock()
		if active {
			m.downloadMu.Unlock()
			return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_BUSY", "该连接已有下载任务正在运行", "file_download", false)
		}
	}
	jobContext, cancel := context.WithCancel(ctx)
	jobID := "download-" + uuid.NewString()
	job := &downloadJob{
		request: request, ctx: jobContext, cancel: cancel,
		progress: model.DownloadProgress{
			JobID: jobID, ProfileID: request.ProfileID,
			State: model.DownloadQueued, StartedAtMS: time.Now().UnixMilli(),
		},
	}
	m.downloads[jobID] = job
	m.downloadMu.Unlock()

	initial := m.updateDownload(job, true, nil)
	go m.runDownload(job)
	return initial, nil
}

func (m *Manager) DownloadStatus(jobID string) (model.DownloadProgress, error) {
	m.downloadMu.RLock()
	job := m.downloads[jobID]
	m.downloadMu.RUnlock()
	if job == nil {
		return model.DownloadProgress{}, model.NewAppError("DOWNLOAD_NOT_FOUND", "下载任务不存在", "file_download", false)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	return job.progress, nil
}

func (m *Manager) CancelDownload(jobID string) error {
	m.downloadMu.RLock()
	job := m.downloads[jobID]
	m.downloadMu.RUnlock()
	if job == nil {
		return model.NewAppError("DOWNLOAD_NOT_FOUND", "下载任务不存在", "file_download", false)
	}
	job.mu.Lock()
	active := downloadStateActive(job.progress.State)
	job.mu.Unlock()
	if active {
		job.cancel()
	}
	return nil
}

func (m *Manager) ActiveDownloadCount(profileID string) int {
	m.downloadMu.RLock()
	defer m.downloadMu.RUnlock()
	count := 0
	for _, job := range m.downloads {
		job.mu.Lock()
		if job.progress.ProfileID == profileID && downloadStateActive(job.progress.State) {
			count++
		}
		job.mu.Unlock()
	}
	return count
}

func (m *Manager) CancelProfileDownloads(profileID string) {
	m.downloadMu.RLock()
	jobs := make([]*downloadJob, 0)
	for _, job := range m.downloads {
		job.mu.Lock()
		matches := job.progress.ProfileID == profileID && downloadStateActive(job.progress.State)
		job.mu.Unlock()
		if matches {
			jobs = append(jobs, job)
		}
	}
	m.downloadMu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

func (m *Manager) CancelAllDownloads() {
	m.downloadMu.RLock()
	jobs := make([]*downloadJob, 0, len(m.downloads))
	for _, job := range m.downloads {
		job.mu.Lock()
		active := downloadStateActive(job.progress.State)
		job.mu.Unlock()
		if active {
			jobs = append(jobs, job)
		}
	}
	m.downloadMu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

func downloadStateActive(state model.DownloadState) bool {
	return state == model.DownloadQueued || state == model.DownloadScanning || state == model.DownloadDownloading
}

func (m *Manager) runDownload(job *downloadJob) {
	m.updateDownload(job, true, func(progress *model.DownloadProgress) {
		progress.State = model.DownloadScanning
	})
	runtime := m.runtime(job.request.ProfileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		m.finishDownload(job, model.NewAppError("SSH_SESSION_FAILED", "SSH 连接已断开", "file_download", true))
		return
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		m.finishDownload(job, model.NewAppError("SFTP_UNAVAILABLE", "远端 SSH 服务未提供 SFTP 子系统", "file_download", false))
		return
	}
	defer sftpClient.Close()
	plan, err := buildDownloadPlan(job.ctx, sftpClient, job.request.RemotePaths, func(name string) {
		m.updateDownload(job, false, func(progress *model.DownloadProgress) {
			progress.CurrentItem = name
		})
	})
	if err != nil {
		m.finishDownload(job, err)
		return
	}
	if err := preflightDownload(job.ctx, job.request.LocalDirectory, plan, job.request.Overwrite); err != nil {
		m.finishDownload(job, err)
		return
	}
	m.updateDownload(job, true, func(progress *model.DownloadProgress) {
		progress.State = model.DownloadDownloading
		progress.CurrentItem = "准备本地目录"
		progress.FilesTotal = len(plan.files)
		progress.DirectoriesTotal = len(plan.directories)
		progress.BytesTotal = plan.totalBytes
	})
	for _, entry := range plan.directories {
		if err := job.ctx.Err(); err != nil {
			m.finishDownload(job, err)
			return
		}
		destination, err := safeLocalDestination(job.request.LocalDirectory, entry.relativePath)
		if err != nil {
			m.finishDownload(job, err)
			return
		}
		if err := os.MkdirAll(destination, 0o755); err != nil {
			m.finishDownload(job, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法创建本地目录“%s”", entry.displayName), "file_download", true))
			return
		}
		m.updateDownload(job, true, func(progress *model.DownloadProgress) {
			progress.DirectoriesCompleted++
		})
	}
	fileConcurrency := min(3, len(plan.files))
	m.updateDownload(job, true, func(progress *model.DownloadProgress) {
		progress.ConcurrentFiles = fileConcurrency
	})
	transferContext, stopTransfers := context.WithCancel(job.ctx)
	defer stopTransfers()
	entries := make(chan downloadEntry)
	errorsChannel := make(chan error, 1)
	var workers sync.WaitGroup
	for worker := 0; worker < fileConcurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for entry := range entries {
				if transferContext.Err() != nil {
					return
				}
				destination, destinationErr := safeLocalDestination(job.request.LocalDirectory, entry.relativePath)
				if destinationErr == nil {
					m.updateDownload(job, true, func(progress *model.DownloadProgress) {
						progress.CurrentItem = entry.displayName
					})
					_, destinationErr = downloadFile(transferContext, sftpClient, entry, destination, job.request.Overwrite, job.request.Resume, func(delta int64) {
						m.updateDownload(job, false, func(progress *model.DownloadProgress) {
							progress.BytesTransferred += delta
						})
					}, func(resumed int64) {
						m.updateDownload(job, true, func(progress *model.DownloadProgress) {
							progress.BytesTransferred += resumed
							progress.BytesResumed += resumed
						})
					})
				}
				if destinationErr != nil {
					select {
					case errorsChannel <- destinationErr:
						stopTransfers()
					default:
					}
					return
				}
				m.updateDownload(job, true, func(progress *model.DownloadProgress) {
					progress.FilesCompleted++
				})
			}
		}()
	}
dispatchLoop:
	for _, entry := range plan.files {
		select {
		case entries <- entry:
		case <-transferContext.Done():
			break dispatchLoop
		}
	}
	close(entries)
	workers.Wait()
	select {
	case transferErr := <-errorsChannel:
		m.finishDownload(job, transferErr)
		return
	default:
	}
	if err := job.ctx.Err(); err != nil {
		m.finishDownload(job, err)
		return
	}
	for index := len(plan.directories) - 1; index >= 0; index-- {
		entry := plan.directories[index]
		destination, err := safeLocalDestination(job.request.LocalDirectory, entry.relativePath)
		if err == nil {
			_ = os.Chtimes(destination, entry.modTime, entry.modTime)
		}
	}
	m.updateDownload(job, true, func(progress *model.DownloadProgress) {
		progress.State = model.DownloadCompleted
		progress.CurrentItem = ""
		progress.FinishedAtMS = time.Now().UnixMilli()
	})
	job.cancel()
	m.expireDownload(job.progress.JobID, job)
}

func (m *Manager) finishDownload(job *downloadJob, err error) {
	state := model.DownloadFailed
	code := "DOWNLOAD_FAILED"
	message := "下载失败"
	if errors.Is(err, context.Canceled) || errors.Is(job.ctx.Err(), context.Canceled) {
		state = model.DownloadCancelled
		code = "DOWNLOAD_CANCELLED"
		message = "下载已取消"
	} else {
		var appError *model.AppError
		if errors.As(err, &appError) {
			code = appError.Code
			message = appError.Message
		}
	}
	m.updateDownload(job, true, func(progress *model.DownloadProgress) {
		progress.State = state
		progress.ErrorCode = code
		progress.ErrorMessage = message
		progress.FinishedAtMS = time.Now().UnixMilli()
	})
	job.cancel()
	m.expireDownload(job.progress.JobID, job)
}

func (m *Manager) expireDownload(jobID string, expected *downloadJob) {
	time.AfterFunc(30*time.Minute, func() {
		m.downloadMu.Lock()
		if m.downloads[jobID] == expected {
			delete(m.downloads, jobID)
		}
		m.downloadMu.Unlock()
	})
}

func (m *Manager) updateDownload(job *downloadJob, force bool, update func(*model.DownloadProgress)) model.DownloadProgress {
	job.mu.Lock()
	if update != nil {
		update(&job.progress)
	}
	value := job.progress
	now := time.Now()
	emit := force || job.lastEmit.IsZero() || now.Sub(job.lastEmit) >= 150*time.Millisecond
	if emit {
		job.lastEmit = now
	}
	job.mu.Unlock()
	if emit {
		m.events.Emit("download:progress", value)
	}
	return value
}

func resolveRemoteLocation(ctx context.Context, client *sftp.Client, requested string) (string, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	workingDirectory, err := client.Getwd()
	if err != nil {
		return "", nil, model.NewAppError("DOWNLOAD_REMOTE_PATH_FAILED", "无法取得远端用户目录", "file_download", true)
	}
	requested = strings.TrimSpace(requested)
	switch {
	case requested == "" || requested == "." || requested == "~":
		requested = workingDirectory
	case strings.HasPrefix(requested, "~/"):
		requested = path.Join(workingDirectory, strings.TrimPrefix(requested, "~/"))
	case strings.HasPrefix(requested, "~"):
		return "", nil, model.NewAppError("DOWNLOAD_REMOTE_PATH_FAILED", "远端路径只支持“~”或“~/子目录”", "file_download", false)
	case !path.IsAbs(requested):
		requested = path.Join(workingDirectory, requested)
	default:
		requested = path.Clean(requested)
	}
	info, err := client.Lstat(requested)
	if err != nil {
		return "", nil, model.NewAppError("DOWNLOAD_REMOTE_PATH_FAILED", "远端路径不存在或不可访问", "file_download", false)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, model.NewAppError("DOWNLOAD_SYMLINK_UNSUPPORTED", "不跟随远端符号链接，请选择实际路径", "file_download", false)
	}
	resolved, realPathErr := client.RealPath(requested)
	if realPathErr == nil && resolved != "" {
		requested = path.Clean(resolved)
		if resolvedInfo, statErr := client.Lstat(requested); statErr == nil {
			info = resolvedInfo
		}
	}
	return path.Clean(requested), info, nil
}

func buildDownloadPlan(ctx context.Context, client *sftp.Client, remotePaths []string, onScan func(string)) (downloadPlan, error) {
	plan := downloadPlan{}
	seenRemote := make(map[string]struct{})
	seenLocal := make(map[string]struct{})
	for _, selectedPath := range remotePaths {
		resolved, info, err := resolveRemoteLocation(ctx, client, selectedPath)
		if err != nil {
			return downloadPlan{}, err
		}
		if _, exists := seenRemote[resolved]; exists {
			continue
		}
		seenRemote[resolved] = struct{}{}
		name := path.Base(resolved)
		if resolved == "/" || !validLocalComponent(name) {
			return downloadPlan{}, model.NewAppError("DOWNLOAD_LOCAL_NAME_UNSUPPORTED", fmt.Sprintf("远端项目名称“%s”无法安全保存到 Windows", name), "file_download", false)
		}
		if info.IsDir() {
			if err := scanRemoteDirectory(ctx, client, resolved, name, &plan, seenLocal, onScan); err != nil {
				return downloadPlan{}, err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return downloadPlan{}, model.NewAppError("DOWNLOAD_REMOTE_TYPE_UNSUPPORTED", fmt.Sprintf("远端项目“%s”不是普通文件或文件夹", name), "file_download", false)
		}
		entry := downloadEntry{remotePath: resolved, relativePath: name, displayName: name, size: info.Size(), modTime: info.ModTime(), mode: info.Mode()}
		if err := addDownloadEntry(&plan, entry, seenLocal); err != nil {
			return downloadPlan{}, err
		}
		if onScan != nil {
			onScan(name)
		}
	}
	return plan, nil
}

func scanRemoteDirectory(ctx context.Context, client *sftp.Client, remoteRoot string, relativeRoot string, plan *downloadPlan, seen map[string]struct{}, onScan func(string)) error {
	info, err := client.Lstat(remoteRoot)
	if err != nil {
		return model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", fmt.Sprintf("无法读取远端目录“%s”", relativeRoot), "file_download", true)
	}
	rootEntry := downloadEntry{remotePath: remoteRoot, relativePath: relativeRoot, displayName: relativeRoot, modTime: info.ModTime(), mode: info.Mode(), isDirectory: true}
	if err := addDownloadEntry(plan, rootEntry, seen); err != nil {
		return err
	}
	if onScan != nil {
		onScan(relativeRoot)
	}
	children, err := client.ReadDir(remoteRoot)
	if err != nil {
		return model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", fmt.Sprintf("无法读取远端目录“%s”", relativeRoot), "file_download", true)
	}
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validLocalComponent(child.Name()) {
			return model.NewAppError("DOWNLOAD_LOCAL_NAME_UNSUPPORTED", fmt.Sprintf("远端项目名称“%s”无法安全保存到 Windows", child.Name()), "file_download", false)
		}
		childRemote := path.Join(remoteRoot, child.Name())
		childRelative := path.Join(relativeRoot, child.Name())
		if child.Mode()&os.ModeSymlink != 0 {
			return model.NewAppError("DOWNLOAD_SYMLINK_UNSUPPORTED", fmt.Sprintf("远端文件夹包含符号链接“%s”，未跟随下载", childRelative), "file_download", false)
		}
		if child.IsDir() {
			if err := scanRemoteDirectory(ctx, client, childRemote, childRelative, plan, seen, onScan); err != nil {
				return err
			}
			continue
		}
		if !child.Mode().IsRegular() {
			return model.NewAppError("DOWNLOAD_REMOTE_TYPE_UNSUPPORTED", fmt.Sprintf("远端项目“%s”不是普通文件或文件夹", childRelative), "file_download", false)
		}
		entry := downloadEntry{remotePath: childRemote, relativePath: childRelative, displayName: childRelative, size: child.Size(), modTime: child.ModTime(), mode: child.Mode()}
		if err := addDownloadEntry(plan, entry, seen); err != nil {
			return err
		}
		if onScan != nil {
			onScan(childRelative)
		}
	}
	return nil
}

func addDownloadEntry(plan *downloadPlan, entry downloadEntry, seen map[string]struct{}) error {
	key := strings.ToLower(entry.relativePath)
	if _, exists := seen[key]; exists {
		return model.NewAppError("DOWNLOAD_DESTINATION_CONFLICT", fmt.Sprintf("多个所选项目会写入同一本地路径“%s”", entry.displayName), "file_download", false)
	}
	seen[key] = struct{}{}
	if entry.isDirectory {
		plan.directories = append(plan.directories, entry)
		return nil
	}
	if entry.size > 0 && plan.totalBytes > math.MaxInt64-entry.size {
		return model.NewAppError("DOWNLOAD_TOO_LARGE", "所选文件总大小超出支持范围", "file_download", false)
	}
	plan.totalBytes += entry.size
	plan.files = append(plan.files, entry)
	return nil
}

func validLocalComponent(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/:*?\"<>|\x00") || strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, value := range name {
		if value < 32 {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}

func safeLocalDestination(root string, relative string) (string, error) {
	destination := filepath.Join(root, filepath.FromSlash(relative))
	relativeCheck, err := filepath.Rel(root, destination)
	if err != nil || relativeCheck == ".." || strings.HasPrefix(relativeCheck, ".."+string(filepath.Separator)) || filepath.IsAbs(relativeCheck) {
		return "", model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", "下载目标路径越出所选本地目录", "file_download", false)
	}
	return destination, nil
}

func preflightDownload(ctx context.Context, localRoot string, plan downloadPlan, overwrite bool) error {
	for _, entry := range plan.directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		destination, err := safeLocalDestination(localRoot, entry.relativePath)
		if err != nil {
			return err
		}
		info, statErr := os.Lstat(destination)
		if statErr == nil && !info.IsDir() {
			return model.NewAppError("DOWNLOAD_CONFLICT", fmt.Sprintf("本地已存在同名文件“%s”，无法创建文件夹", entry.displayName), "file_download", false)
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", fmt.Sprintf("无法检查本地路径“%s”", entry.displayName), "file_download", true)
		}
	}
	for _, entry := range plan.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		destination, err := safeLocalDestination(localRoot, entry.relativePath)
		if err != nil {
			return err
		}
		info, statErr := os.Lstat(destination)
		if statErr == nil {
			if info.IsDir() {
				return model.NewAppError("DOWNLOAD_CONFLICT", fmt.Sprintf("本地已存在同名文件夹“%s”", entry.displayName), "file_download", false)
			}
			if !overwrite {
				return model.NewAppError("DOWNLOAD_CONFLICT", fmt.Sprintf("本地已存在“%s”；勾选覆盖后可替换", entry.displayName), "file_download", false)
			}
		} else if !os.IsNotExist(statErr) {
			return model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", fmt.Sprintf("无法检查本地文件“%s”", entry.displayName), "file_download", true)
		}
	}
	return nil
}

func downloadFile(ctx context.Context, client *sftp.Client, entry downloadEntry, destination string, overwrite bool, resume bool, onBytes func(int64), onResume func(int64)) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return 0, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法创建“%s”的本地父目录", entry.displayName), "file_download", true)
	}
	temporary, temporaryPrefix := resumableDownloadPath(entry, destination)
	if err := cleanStaleDownloadParts(filepath.Dir(destination), temporaryPrefix, temporary); err != nil {
		return 0, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法清理“%s”的旧续传文件", entry.displayName), "file_download", true)
	}
	resumeOffset := int64(0)
	if partialInfo, statErr := os.Lstat(temporary); statErr == nil {
		if !resume || !partialInfo.Mode().IsRegular() || partialInfo.Size() > entry.size {
			if removeErr := os.Remove(temporary); removeErr != nil {
				return 0, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法重置“%s”的续传文件", entry.displayName), "file_download", true)
			}
		} else {
			resumeOffset = partialInfo.Size()
		}
	} else if !os.IsNotExist(statErr) {
		return 0, model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", fmt.Sprintf("无法检查“%s”的续传文件", entry.displayName), "file_download", true)
	}
	remoteFile, err := client.Open(entry.remotePath)
	if err != nil {
		return 0, model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", fmt.Sprintf("无法打开远端文件“%s”", entry.displayName), "file_download", true)
	}
	defer remoteFile.Close()
	openFlags := os.O_WRONLY | os.O_CREATE
	if resumeOffset == 0 {
		openFlags |= os.O_TRUNC
	}
	localFile, err := os.OpenFile(temporary, openFlags, 0o600)
	if err != nil {
		return 0, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法创建本地文件“%s”", entry.displayName), "file_download", true)
	}
	if resumeOffset > 0 {
		if _, err := remoteFile.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = localFile.Close()
			return 0, model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", fmt.Sprintf("无法定位“%s”的远端续传位置", entry.displayName), "file_download", true)
		}
		if _, err := localFile.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = localFile.Close()
			return 0, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法定位“%s”的本地续传位置", entry.displayName), "file_download", true)
		}
		if onResume != nil {
			onResume(resumeOffset)
		}
	}
	writer := &downloadProgressWriter{ctx: ctx, writer: localFile, onBytes: onBytes}
	writtenNow, copyErr := remoteFile.WriteTo(writer)
	written := resumeOffset + writtenNow
	if copyErr == nil {
		if syncErr := localFile.Sync(); syncErr != nil {
			_ = localFile.Close()
			return written, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("写入本地文件“%s”失败", entry.displayName), "file_download", true)
		}
	}
	closeErr := localFile.Close()
	if copyErr != nil {
		if errors.Is(copyErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return written, context.Canceled
		}
		if writer.writeErr != nil {
			return written, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("写入本地文件“%s”失败", entry.displayName), "file_download", true)
		}
		return written, model.NewAppError("DOWNLOAD_REMOTE_READ_FAILED", fmt.Sprintf("读取远端文件“%s”失败", entry.displayName), "file_download", true)
	}
	if closeErr != nil {
		return written, model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("提交本地文件“%s”失败", entry.displayName), "file_download", true)
	}
	if written != entry.size {
		_ = os.Remove(temporary)
		return written, model.NewAppError("DOWNLOAD_REMOTE_CHANGED", fmt.Sprintf("下载期间远端文件“%s”发生变化，请重试", entry.displayName), "file_download", true)
	}
	remoteInfo, err := client.Lstat(entry.remotePath)
	if err != nil || !remoteInfo.Mode().IsRegular() || remoteInfo.Size() != entry.size || remoteInfo.ModTime().Unix() != entry.modTime.Unix() {
		_ = os.Remove(temporary)
		return written, model.NewAppError("DOWNLOAD_REMOTE_CHANGED", fmt.Sprintf("下载期间远端文件“%s”发生变化，请重试", entry.displayName), "file_download", true)
	}
	_ = os.Chmod(temporary, entry.mode.Perm())
	_ = os.Chtimes(temporary, entry.modTime, entry.modTime)
	if err := ctx.Err(); err != nil {
		return written, err
	}
	if err := commitDownloadedFile(temporary, destination, overwrite, entry.displayName); err != nil {
		return written, err
	}
	return written, nil
}

type downloadProgressWriter struct {
	ctx      context.Context
	writer   io.Writer
	onBytes  func(int64)
	writeErr error
}

func (writer *downloadProgressWriter) Write(buffer []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := writer.writer.Write(buffer)
	if err != nil {
		writer.writeErr = err
	}
	if count > 0 && writer.onBytes != nil {
		writer.onBytes(int64(count))
	}
	return count, err
}

func resumableDownloadPath(entry downloadEntry, destination string) (string, string) {
	destinationHash := sha256.Sum256([]byte(strings.ToLower(destination)))
	fingerprint := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", entry.remotePath, entry.size, entry.modTime.UnixNano())))
	prefix := fmt.Sprintf(".labremote-%x-", destinationHash[:6])
	return filepath.Join(filepath.Dir(destination), fmt.Sprintf("%s%x.part", prefix, fingerprint[:6])), prefix
}

func cleanStaleDownloadParts(directory string, prefix string, keep string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		candidate := filepath.Join(directory, entry.Name())
		if !strings.EqualFold(candidate, keep) {
			if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func commitDownloadedFile(temporary string, destination string, overwrite bool, displayName string) error {
	if _, err := os.Lstat(destination); err == nil {
		if !overwrite {
			return model.NewAppError("DOWNLOAD_CONFLICT", fmt.Sprintf("本地已存在“%s”；勾选覆盖后可替换", displayName), "file_download", false)
		}
		backup := filepath.Join(filepath.Dir(destination), ".labremote-backup-"+uuid.NewString())
		if err := os.Rename(destination, backup); err != nil {
			return model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法替换本地文件“%s”", displayName), "file_download", true)
		}
		if err := os.Rename(temporary, destination); err != nil {
			_ = os.Rename(backup, destination)
			return model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法提交本地文件“%s”", displayName), "file_download", true)
		}
		_ = os.Remove(backup)
		return nil
	} else if !os.IsNotExist(err) {
		return model.NewAppError("DOWNLOAD_LOCAL_PATH_FAILED", fmt.Sprintf("无法检查本地文件“%s”", displayName), "file_download", true)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return model.NewAppError("DOWNLOAD_LOCAL_WRITE_FAILED", fmt.Sprintf("无法提交本地文件“%s”", displayName), "file_download", true)
	}
	return nil
}
