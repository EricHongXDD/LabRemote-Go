package model

type RemoteEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	IsDirectory bool   `json:"is_directory"`
	IsSymlink   bool   `json:"is_symlink"`
	Size        int64  `json:"size"`
	ModTimeMS   int64  `json:"mod_time_ms"`
}

type RemoteDirectory struct {
	Path    string        `json:"path"`
	Parent  string        `json:"parent"`
	Entries []RemoteEntry `json:"entries"`
}

type DownloadState string

const (
	DownloadQueued      DownloadState = "queued"
	DownloadScanning    DownloadState = "scanning"
	DownloadDownloading DownloadState = "downloading"
	DownloadCompleted   DownloadState = "completed"
	DownloadFailed      DownloadState = "failed"
	DownloadCancelled   DownloadState = "cancelled"
)

type DownloadRequest struct {
	ProfileID      string   `json:"profile_id"`
	RemotePaths    []string `json:"remote_paths"`
	LocalDirectory string   `json:"local_directory"`
	Overwrite      bool     `json:"overwrite"`
	Resume         bool     `json:"resume"`
}

type DownloadProgress struct {
	JobID                string        `json:"job_id"`
	ProfileID            string        `json:"profile_id"`
	State                DownloadState `json:"state"`
	CurrentItem          string        `json:"current_item,omitempty"`
	FilesTotal           int           `json:"files_total"`
	DirectoriesTotal     int           `json:"directories_total"`
	BytesTotal           int64         `json:"bytes_total"`
	FilesCompleted       int           `json:"files_completed"`
	DirectoriesCompleted int           `json:"directories_completed"`
	BytesTransferred     int64         `json:"bytes_transferred"`
	BytesResumed         int64         `json:"bytes_resumed"`
	ConcurrentFiles      int           `json:"concurrent_files"`
	ErrorCode            string        `json:"error_code,omitempty"`
	ErrorMessage         string        `json:"error_message,omitempty"`
	StartedAtMS          int64         `json:"started_at_ms"`
	FinishedAtMS         int64         `json:"finished_at_ms,omitempty"`
}
