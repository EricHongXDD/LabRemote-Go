package sshclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/google/uuid"
	"github.com/pkg/sftp"
)

type uploadJob struct {
	request  model.UploadRequest
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	progress model.UploadProgress
	lastEmit time.Time
}

type uploadEntry struct {
	localPath    string
	relativePath string
	displayName  string
	size         int64
	modTime      time.Time
	isDirectory  bool
}

type uploadPlan struct {
	directories []uploadEntry
	files       []uploadEntry
	totalBytes  int64
}

func (m *Manager) StartUpload(ctx context.Context, request model.UploadRequest) (model.UploadProgress, error) {
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	request.RemoteDirectory = strings.TrimSpace(request.RemoteDirectory)
	if request.ProfileID == "" {
		return model.UploadProgress{}, model.NewAppError("UPLOAD_INVALID", "未选择连接配置", "file_upload", false)
	}
	if len(request.LocalPaths) == 0 {
		return model.UploadProgress{}, model.NewAppError("UPLOAD_INVALID", "请至少选择一个文件或文件夹", "file_upload", false)
	}
	if strings.ContainsRune(request.RemoteDirectory, '\x00') || len(request.RemoteDirectory) > 4096 {
		return model.UploadProgress{}, model.NewAppError("UPLOAD_INVALID", "远端目录无效", "file_upload", false)
	}
	runtime := m.runtime(request.ProfileID)
	runtime.mu.Lock()
	connected := runtime.client != nil
	runtime.mu.Unlock()
	if !connected {
		return model.UploadProgress{}, model.NewAppError("SSH_SESSION_FAILED", "SSH 客户端未连接", "file_upload", true)
	}

	m.uploadMu.Lock()
	for _, existing := range m.uploads {
		existing.mu.Lock()
		active := existing.progress.ProfileID == request.ProfileID && uploadStateActive(existing.progress.State)
		existing.mu.Unlock()
		if active {
			m.uploadMu.Unlock()
			return model.UploadProgress{}, model.NewAppError("UPLOAD_BUSY", "该连接已有上传任务正在运行", "file_upload", false)
		}
	}
	jobContext, cancel := context.WithCancel(ctx)
	jobID := "upload-" + uuid.NewString()
	job := &uploadJob{
		request: request,
		ctx:     jobContext,
		cancel:  cancel,
		progress: model.UploadProgress{
			JobID:       jobID,
			ProfileID:   request.ProfileID,
			State:       model.UploadQueued,
			StartedAtMS: time.Now().UnixMilli(),
		},
	}
	m.uploads[jobID] = job
	m.uploadMu.Unlock()

	initial := m.updateUpload(job, true, nil)
	go m.runUpload(job)
	return initial, nil
}

func (m *Manager) UploadStatus(jobID string) (model.UploadProgress, error) {
	m.uploadMu.RLock()
	job := m.uploads[jobID]
	m.uploadMu.RUnlock()
	if job == nil {
		return model.UploadProgress{}, model.NewAppError("UPLOAD_NOT_FOUND", "上传任务不存在", "file_upload", false)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	return job.progress, nil
}

func (m *Manager) CancelUpload(jobID string) error {
	m.uploadMu.RLock()
	job := m.uploads[jobID]
	m.uploadMu.RUnlock()
	if job == nil {
		return model.NewAppError("UPLOAD_NOT_FOUND", "上传任务不存在", "file_upload", false)
	}
	job.mu.Lock()
	active := uploadStateActive(job.progress.State)
	job.mu.Unlock()
	if active {
		job.cancel()
	}
	return nil
}

func (m *Manager) ActiveUploadCount(profileID string) int {
	m.uploadMu.RLock()
	defer m.uploadMu.RUnlock()
	count := 0
	for _, job := range m.uploads {
		job.mu.Lock()
		if job.progress.ProfileID == profileID && uploadStateActive(job.progress.State) {
			count++
		}
		job.mu.Unlock()
	}
	return count
}

func (m *Manager) CancelProfileUploads(profileID string) {
	m.uploadMu.RLock()
	jobs := make([]*uploadJob, 0)
	for _, job := range m.uploads {
		job.mu.Lock()
		matches := job.progress.ProfileID == profileID && uploadStateActive(job.progress.State)
		job.mu.Unlock()
		if matches {
			jobs = append(jobs, job)
		}
	}
	m.uploadMu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

func (m *Manager) CancelAllUploads() {
	m.uploadMu.RLock()
	jobs := make([]*uploadJob, 0, len(m.uploads))
	for _, job := range m.uploads {
		job.mu.Lock()
		active := uploadStateActive(job.progress.State)
		job.mu.Unlock()
		if active {
			jobs = append(jobs, job)
		}
	}
	m.uploadMu.RUnlock()
	for _, job := range jobs {
		job.cancel()
	}
}

func uploadStateActive(state model.UploadState) bool {
	return state == model.UploadQueued || state == model.UploadScanning || state == model.UploadUploading
}

func (m *Manager) runUpload(job *uploadJob) {
	m.updateUpload(job, true, func(progress *model.UploadProgress) {
		progress.State = model.UploadScanning
	})
	plan, err := buildUploadPlan(job.ctx, job.request.LocalPaths, func(name string) {
		m.updateUpload(job, false, func(progress *model.UploadProgress) {
			progress.CurrentItem = name
		})
	})
	if err != nil {
		m.finishUpload(job, err)
		return
	}
	m.updateUpload(job, true, func(progress *model.UploadProgress) {
		progress.State = model.UploadUploading
		progress.CurrentItem = "准备远端目录"
		progress.FilesTotal = len(plan.files)
		progress.DirectoriesTotal = len(plan.directories)
		progress.BytesTotal = plan.totalBytes
	})

	runtime := m.runtime(job.request.ProfileID)
	runtime.mu.Lock()
	client := runtime.client
	runtime.mu.Unlock()
	if client == nil {
		m.finishUpload(job, model.NewAppError("SSH_SESSION_FAILED", "SSH 连接已断开", "file_upload", true))
		return
	}
	sftpClient, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		m.finishUpload(job, model.NewAppError("SFTP_UNAVAILABLE", "远端 SSH 服务未提供 SFTP 子系统", "file_upload", false))
		return
	}
	defer sftpClient.Close()

	remoteRoot, err := prepareRemoteRoot(job.ctx, sftpClient, job.request.RemoteDirectory)
	if err != nil {
		m.finishUpload(job, err)
		return
	}
	if err := preflightUpload(job.ctx, sftpClient, remoteRoot, plan, job.request.Overwrite); err != nil {
		m.finishUpload(job, err)
		return
	}
	for _, entry := range plan.directories {
		if err := job.ctx.Err(); err != nil {
			m.finishUpload(job, err)
			return
		}
		m.updateUpload(job, true, func(progress *model.UploadProgress) {
			progress.CurrentItem = entry.displayName
		})
		destination := path.Join(remoteRoot, entry.relativePath)
		if err := sftpClient.MkdirAll(destination); err != nil {
			m.finishUpload(job, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法创建远端目录“%s”", entry.displayName), "file_upload", true))
			return
		}
		m.updateUpload(job, true, func(progress *model.UploadProgress) {
			progress.DirectoriesCompleted++
		})
	}
	fileConcurrency := min(3, len(plan.files))
	m.updateUpload(job, true, func(progress *model.UploadProgress) {
		progress.ConcurrentFiles = fileConcurrency
	})
	transferContext, stopTransfers := context.WithCancel(job.ctx)
	defer stopTransfers()
	entries := make(chan uploadEntry)
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
				m.updateUpload(job, true, func(progress *model.UploadProgress) {
					progress.CurrentItem = entry.displayName
				})
				destination := path.Join(remoteRoot, entry.relativePath)
				written, uploadErr := uploadFile(transferContext, sftpClient, entry, destination, job.request.Overwrite, job.request.Resume, func(delta int64) {
					m.updateUpload(job, false, func(progress *model.UploadProgress) {
						progress.BytesTransferred += delta
					})
				}, func(resumed int64) {
					m.updateUpload(job, true, func(progress *model.UploadProgress) {
						progress.BytesTransferred += resumed
						progress.BytesResumed += resumed
					})
				})
				if uploadErr == nil && written != entry.size {
					uploadErr = model.NewAppError("UPLOAD_LOCAL_CHANGED", fmt.Sprintf("上传期间本地文件“%s”发生变化，请重试", entry.displayName), "file_upload", true)
				}
				if uploadErr != nil {
					select {
					case errorsChannel <- uploadErr:
						stopTransfers()
					default:
					}
					return
				}
				m.updateUpload(job, true, func(progress *model.UploadProgress) {
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
		m.finishUpload(job, transferErr)
		return
	default:
	}
	if err := job.ctx.Err(); err != nil {
		m.finishUpload(job, err)
		return
	}
	m.updateUpload(job, true, func(progress *model.UploadProgress) {
		progress.State = model.UploadCompleted
		progress.CurrentItem = ""
		progress.FinishedAtMS = time.Now().UnixMilli()
	})
	job.cancel()
	m.expireUpload(job.progress.JobID, job)
}

func (m *Manager) finishUpload(job *uploadJob, err error) {
	state := model.UploadFailed
	code := "UPLOAD_FAILED"
	message := "上传失败"
	if errors.Is(err, context.Canceled) || errors.Is(job.ctx.Err(), context.Canceled) {
		state = model.UploadCancelled
		code = "UPLOAD_CANCELLED"
		message = "上传已取消"
	} else {
		var appError *model.AppError
		if errors.As(err, &appError) {
			code = appError.Code
			message = appError.Message
		}
	}
	m.updateUpload(job, true, func(progress *model.UploadProgress) {
		progress.State = state
		progress.ErrorCode = code
		progress.ErrorMessage = message
		progress.FinishedAtMS = time.Now().UnixMilli()
	})
	job.cancel()
	m.expireUpload(job.progress.JobID, job)
}

func (m *Manager) expireUpload(jobID string, expected *uploadJob) {
	time.AfterFunc(30*time.Minute, func() {
		m.uploadMu.Lock()
		if m.uploads[jobID] == expected {
			delete(m.uploads, jobID)
		}
		m.uploadMu.Unlock()
	})
}

func (m *Manager) updateUpload(job *uploadJob, force bool, update func(*model.UploadProgress)) model.UploadProgress {
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
		m.events.Emit("upload:progress", value)
	}
	return value
}

func buildUploadPlan(ctx context.Context, localPaths []string, onScan func(string)) (uploadPlan, error) {
	plan := uploadPlan{}
	seenLocal := make(map[string]struct{})
	seenRemote := make(map[string]struct{})
	for _, selectedPath := range localPaths {
		if err := ctx.Err(); err != nil {
			return uploadPlan{}, err
		}
		absolute, err := filepath.Abs(strings.TrimSpace(selectedPath))
		if err != nil {
			return uploadPlan{}, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", "无法解析所选本地路径", "file_upload", false)
		}
		absolute = filepath.Clean(absolute)
		localKey := strings.ToLower(absolute)
		if _, exists := seenLocal[localKey]; exists {
			continue
		}
		seenLocal[localKey] = struct{}{}
		info, err := os.Lstat(absolute)
		if err != nil {
			return uploadPlan{}, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", "无法读取所选本地项目", "file_upload", false)
		}
		name := filepath.Base(absolute)
		if name == "." || name == string(filepath.Separator) || name == "" {
			return uploadPlan{}, model.NewAppError("UPLOAD_INVALID", "不支持直接上传磁盘或文件系统根目录", "file_upload", false)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return uploadPlan{}, model.NewAppError("UPLOAD_SYMLINK_UNSUPPORTED", fmt.Sprintf("所选项目“%s”是符号链接，未跟随上传", name), "file_upload", false)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return uploadPlan{}, model.NewAppError("UPLOAD_LOCAL_TYPE_UNSUPPORTED", fmt.Sprintf("所选项目“%s”不是普通文件或文件夹", name), "file_upload", false)
		}
		if onScan != nil {
			onScan(name)
		}
		if info.Mode().IsRegular() {
			entry := uploadEntry{localPath: absolute, relativePath: name, displayName: name, size: info.Size(), modTime: info.ModTime()}
			if err := addUploadEntry(&plan, entry, seenRemote); err != nil {
				return uploadPlan{}, err
			}
			continue
		}
		err = filepath.WalkDir(absolute, func(current string, directoryEntry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			relative, relErr := filepath.Rel(absolute, current)
			if relErr != nil {
				return model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法扫描文件夹“%s”", name), "file_upload", false)
			}
			display := name
			if relative != "." {
				display = path.Join(name, filepath.ToSlash(relative))
			}
			if walkErr != nil {
				return model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法读取“%s”", display), "file_upload", false)
			}
			if directoryEntry.Type()&os.ModeSymlink != 0 {
				return model.NewAppError("UPLOAD_SYMLINK_UNSUPPORTED", fmt.Sprintf("文件夹包含符号链接“%s”，未跟随上传", display), "file_upload", false)
			}
			entryInfo, infoErr := directoryEntry.Info()
			if infoErr != nil {
				return model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法读取“%s”", display), "file_upload", false)
			}
			entry := uploadEntry{
				localPath: current, relativePath: display, displayName: display,
				size: entryInfo.Size(), modTime: entryInfo.ModTime(), isDirectory: entryInfo.IsDir(),
			}
			if !entryInfo.IsDir() && !entryInfo.Mode().IsRegular() {
				return model.NewAppError("UPLOAD_LOCAL_TYPE_UNSUPPORTED", fmt.Sprintf("“%s”不是普通文件或文件夹", display), "file_upload", false)
			}
			if onScan != nil {
				onScan(display)
			}
			return addUploadEntry(&plan, entry, seenRemote)
		})
		if err != nil {
			return uploadPlan{}, err
		}
	}
	return plan, nil
}

func addUploadEntry(plan *uploadPlan, entry uploadEntry, seen map[string]struct{}) error {
	if _, exists := seen[entry.relativePath]; exists {
		return model.NewAppError("UPLOAD_DESTINATION_CONFLICT", fmt.Sprintf("多个所选项目会写入同一远端路径“%s”", entry.displayName), "file_upload", false)
	}
	seen[entry.relativePath] = struct{}{}
	if entry.isDirectory {
		plan.directories = append(plan.directories, entry)
		return nil
	}
	if entry.size > 0 && plan.totalBytes > math.MaxInt64-entry.size {
		return model.NewAppError("UPLOAD_TOO_LARGE", "所选文件总大小超出支持范围", "file_upload", false)
	}
	plan.totalBytes += entry.size
	plan.files = append(plan.files, entry)
	return nil
}

func prepareRemoteRoot(ctx context.Context, client *sftp.Client, requested string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	workingDirectory, err := client.Getwd()
	if err != nil {
		return "", model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", "无法取得远端用户目录", "file_upload", true)
	}
	requested = strings.TrimSpace(requested)
	switch {
	case requested == "", requested == ".", requested == "~":
		requested = workingDirectory
	case strings.HasPrefix(requested, "~/"):
		requested = path.Join(workingDirectory, strings.TrimPrefix(requested, "~/"))
	case strings.HasPrefix(requested, "~"):
		return "", model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", "远端目录只支持“~”或“~/子目录”，不支持其他用户的主目录缩写", "file_upload", false)
	case !path.IsAbs(requested):
		requested = path.Join(workingDirectory, requested)
	default:
		requested = path.Clean(requested)
	}
	if err := client.MkdirAll(requested); err != nil {
		return "", model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", "无法创建或访问远端目标目录", "file_upload", true)
	}
	info, err := client.Stat(requested)
	if err != nil || !info.IsDir() {
		return "", model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", "远端目标路径不是可访问的目录", "file_upload", false)
	}
	resolved, err := client.RealPath(requested)
	if err == nil && resolved != "" {
		return path.Clean(resolved), nil
	}
	return path.Clean(requested), nil
}

func preflightUpload(ctx context.Context, client *sftp.Client, remoteRoot string, plan uploadPlan, overwrite bool) error {
	for _, entry := range plan.directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := client.Lstat(path.Join(remoteRoot, entry.relativePath))
		if err == nil && !info.IsDir() {
			return model.NewAppError("UPLOAD_CONFLICT", fmt.Sprintf("远端已存在同名文件“%s”，无法创建文件夹", entry.displayName), "file_upload", false)
		}
		if err != nil && !os.IsNotExist(err) {
			return model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", fmt.Sprintf("无法检查远端路径“%s”", entry.displayName), "file_upload", true)
		}
	}
	for _, entry := range plan.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := client.Lstat(path.Join(remoteRoot, entry.relativePath))
		if err == nil {
			if info.IsDir() {
				return model.NewAppError("UPLOAD_CONFLICT", fmt.Sprintf("远端已存在同名文件夹“%s”", entry.displayName), "file_upload", false)
			}
			if !overwrite {
				return model.NewAppError("UPLOAD_CONFLICT", fmt.Sprintf("远端已存在“%s”；勾选覆盖后可替换", entry.displayName), "file_upload", false)
			}
		} else if !os.IsNotExist(err) {
			return model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", fmt.Sprintf("无法检查远端文件“%s”", entry.displayName), "file_upload", true)
		}
	}
	return nil
}

func uploadFile(
	ctx context.Context,
	client *sftp.Client,
	entry uploadEntry,
	destination string,
	overwrite bool,
	resume bool,
	onBytes func(int64),
	onResume func(int64),
) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	localInfo, err := os.Lstat(entry.localPath)
	if err != nil || localInfo.Mode()&os.ModeSymlink != 0 || !localInfo.Mode().IsRegular() {
		return 0, model.NewAppError("UPLOAD_LOCAL_CHANGED", fmt.Sprintf("本地文件“%s”已变化或不可读取", entry.displayName), "file_upload", true)
	}
	localFile, err := os.Open(entry.localPath)
	if err != nil {
		return 0, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法打开本地文件“%s”", entry.displayName), "file_upload", false)
	}
	defer localFile.Close()
	if err := client.MkdirAll(path.Dir(destination)); err != nil {
		return 0, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法创建“%s”的远端父目录", entry.displayName), "file_upload", true)
	}
	temporary, temporaryPrefix, err := resumableUploadPath(localFile, localInfo, destination)
	if err != nil {
		return 0, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法读取本地文件“%s”的续传信息", entry.displayName), "file_upload", true)
	}
	if err := cleanStaleUploadParts(client, path.Dir(destination), temporaryPrefix, temporary); err != nil {
		return 0, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法清理“%s”的旧续传文件", entry.displayName), "file_upload", true)
	}
	targetMode := os.FileMode(0o644)
	if overwrite {
		if existing, statErr := client.Lstat(destination); statErr == nil && !existing.IsDir() && existing.Mode().Perm() != 0 {
			targetMode = existing.Mode().Perm()
		}
	}
	resumeOffset := int64(0)
	if partialInfo, statErr := client.Lstat(temporary); statErr == nil {
		if !resume || !partialInfo.Mode().IsRegular() || partialInfo.Size() > entry.size {
			if removeErr := client.Remove(temporary); removeErr != nil {
				return 0, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法重置“%s”的续传文件", entry.displayName), "file_upload", true)
			}
		} else {
			resumeOffset = partialInfo.Size()
		}
	} else if !os.IsNotExist(statErr) {
		return 0, model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", fmt.Sprintf("无法检查“%s”的续传文件", entry.displayName), "file_upload", true)
	}
	openFlags := os.O_WRONLY | os.O_CREATE
	if resumeOffset == 0 {
		openFlags |= os.O_TRUNC
	}
	remoteFile, err := client.OpenFile(temporary, openFlags)
	if err != nil {
		return 0, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法在远端创建“%s”", entry.displayName), "file_upload", true)
	}
	if resumeOffset > 0 {
		if _, err := localFile.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = remoteFile.Close()
			return 0, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", fmt.Sprintf("无法定位本地文件“%s”的续传位置", entry.displayName), "file_upload", true)
		}
		if _, err := remoteFile.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = remoteFile.Close()
			return 0, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法定位“%s”的远端续传位置", entry.displayName), "file_upload", true)
		}
		if onResume != nil {
			onResume(resumeOffset)
		}
	}
	reader := &uploadProgressReader{ctx: ctx, reader: localFile, onBytes: onBytes}
	writtenNow, copyErr := remoteFile.ReadFromWithConcurrency(reader, 8)
	written := resumeOffset + writtenNow
	if copyErr != nil {
		// 并发写入出错时，SFTP 文件偏移量是可安全保留的最早位置。
		safeOffset, seekErr := remoteFile.Seek(0, io.SeekCurrent)
		closeErr := remoteFile.Close()
		if seekErr == nil {
			_ = client.Truncate(temporary, safeOffset)
			written = safeOffset
		}
		if errors.Is(copyErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return written, context.Canceled
		}
		if closeErr != nil {
			return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("关闭远端文件“%s”失败", entry.displayName), "file_upload", true)
		}
		return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("写入远端文件“%s”失败", entry.displayName), "file_upload", true)
	}
	if written != entry.size {
		_ = remoteFile.Close()
		return written, model.NewAppError("UPLOAD_LOCAL_CHANGED", fmt.Sprintf("上传期间本地文件“%s”发生变化，请重试", entry.displayName), "file_upload", true)
	}
	if copyErr == nil {
		syncErr := remoteFile.Sync()
		var statusError *sftp.StatusError
		if syncErr != nil && (!errors.As(syncErr, &statusError) || statusError.FxCode() != sftp.ErrSSHFxOpUnsupported) {
			copyErr = syncErr
		}
	}
	closeErr := remoteFile.Close()
	if copyErr != nil {
		return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("写入远端文件“%s”失败", entry.displayName), "file_upload", true)
	}
	if closeErr != nil {
		return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("提交远端文件“%s”失败", entry.displayName), "file_upload", true)
	}
	_ = client.Chmod(temporary, targetMode)
	_ = client.Chtimes(temporary, entry.modTime, entry.modTime)
	if err := ctx.Err(); err != nil {
		return written, err
	}
	if overwrite {
		if err := client.PosixRename(temporary, destination); err == nil {
			return written, nil
		}
		info, statErr := client.Lstat(destination)
		if statErr == nil {
			if info.IsDir() {
				return written, model.NewAppError("UPLOAD_CONFLICT", fmt.Sprintf("远端已存在同名文件夹“%s”", entry.displayName), "file_upload", false)
			}
			if err := client.Remove(destination); err != nil {
				return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法替换远端文件“%s”", entry.displayName), "file_upload", true)
			}
		} else if !os.IsNotExist(statErr) {
			return written, model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", fmt.Sprintf("无法检查远端文件“%s”", entry.displayName), "file_upload", true)
		}
	} else {
		if _, err := client.Lstat(destination); err == nil {
			return written, model.NewAppError("UPLOAD_CONFLICT", fmt.Sprintf("远端已存在“%s”；勾选覆盖后可替换", entry.displayName), "file_upload", false)
		} else if !os.IsNotExist(err) {
			return written, model.NewAppError("UPLOAD_REMOTE_PATH_FAILED", fmt.Sprintf("无法检查远端文件“%s”", entry.displayName), "file_upload", true)
		}
	}
	if err := client.Rename(temporary, destination); err != nil {
		return written, model.NewAppError("UPLOAD_REMOTE_WRITE_FAILED", fmt.Sprintf("无法提交远端文件“%s”", entry.displayName), "file_upload", true)
	}
	return written, nil
}

type uploadProgressReader struct {
	ctx     context.Context
	reader  io.Reader
	onBytes func(int64)
}

func (reader *uploadProgressReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if count > 0 && reader.onBytes != nil {
		reader.onBytes(int64(count))
	}
	return count, err
}

func resumableUploadPath(localFile *os.File, info os.FileInfo, destination string) (string, string, error) {
	fingerprint, err := localFileFingerprint(localFile, info)
	if err != nil {
		return "", "", err
	}
	destinationHash := sha256.Sum256([]byte(destination))
	prefix := fmt.Sprintf(".labremote-%x-", destinationHash[:6])
	return path.Join(path.Dir(destination), fmt.Sprintf("%s%x.part", prefix, fingerprint[:6])), prefix, nil
}

func localFileFingerprint(localFile *os.File, info os.FileInfo) ([32]byte, error) {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d:%d:", info.Size(), info.ModTime().UnixNano())
	const sampleSize = 64 * 1024
	firstSize := min(int64(sampleSize), info.Size())
	if firstSize > 0 {
		first := make([]byte, firstSize)
		if _, err := localFile.ReadAt(first, 0); err != nil && !errors.Is(err, io.EOF) {
			return [32]byte{}, err
		}
		_, _ = hash.Write(first)
	}
	lastOffset := max(int64(0), info.Size()-sampleSize)
	if lastOffset > 0 {
		last := make([]byte, info.Size()-lastOffset)
		if _, err := localFile.ReadAt(last, lastOffset); err != nil && !errors.Is(err, io.EOF) {
			return [32]byte{}, err
		}
		_, _ = hash.Write(last)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func cleanStaleUploadParts(client *sftp.Client, directory string, prefix string, keep string) error {
	entries, err := client.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Mode().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		candidate := path.Join(directory, entry.Name())
		if candidate != keep {
			if err := client.Remove(candidate); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func copyUpload(ctx context.Context, destination io.Writer, source io.Reader, onBytes func(int64)) (int64, error) {
	buffer := make([]byte, 256*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			written := 0
			for written < count {
				if err := ctx.Err(); err != nil {
					return total, err
				}
				value, writeErr := destination.Write(buffer[written:count])
				if value > 0 {
					written += value
					total += int64(value)
					if onBytes != nil {
						onBytes(int64(value))
					}
				}
				if writeErr != nil {
					return total, writeErr
				}
				if value == 0 {
					return total, io.ErrShortWrite
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
