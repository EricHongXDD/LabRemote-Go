package model

type UploadState string

const (
	UploadQueued    UploadState = "queued"
	UploadScanning  UploadState = "scanning"
	UploadUploading UploadState = "uploading"
	UploadCompleted UploadState = "completed"
	UploadFailed    UploadState = "failed"
	UploadCancelled UploadState = "cancelled"
)

type UploadSelection struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	IsDirectory bool   `json:"is_directory"`
	Size        int64  `json:"size"`
}

type UploadRequest struct {
	ProfileID       string   `json:"profile_id"`
	LocalPaths      []string `json:"local_paths"`
	RemoteDirectory string   `json:"remote_directory"`
	Overwrite       bool     `json:"overwrite"`
	Resume          bool     `json:"resume"`
}

type UploadProgress struct {
	JobID                string      `json:"job_id"`
	ProfileID            string      `json:"profile_id"`
	State                UploadState `json:"state"`
	CurrentItem          string      `json:"current_item,omitempty"`
	FilesTotal           int         `json:"files_total"`
	DirectoriesTotal     int         `json:"directories_total"`
	BytesTotal           int64       `json:"bytes_total"`
	FilesCompleted       int         `json:"files_completed"`
	DirectoriesCompleted int         `json:"directories_completed"`
	BytesTransferred     int64       `json:"bytes_transferred"`
	BytesResumed         int64       `json:"bytes_resumed"`
	ConcurrentFiles      int         `json:"concurrent_files"`
	ErrorCode            string      `json:"error_code,omitempty"`
	ErrorMessage         string      `json:"error_message,omitempty"`
	StartedAtMS          int64       `json:"started_at_ms"`
	FinishedAtMS         int64       `json:"finished_at_ms,omitempty"`
}
