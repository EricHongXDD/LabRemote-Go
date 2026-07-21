export type MCPPolicy = {
  enabled_for_profile: boolean
  allow_exec: boolean
  allow_interactive: boolean
  allow_disconnect: boolean
}

export type ConnectionMode = 'isolated_tunnel' | 'direct_ssh'
export type SSHAuthMethod = 'password' | 'private_key'

export type ConnectionProfile = {
  id: string
  display_name: string
  group?: string
  connection_mode?: ConnectionMode
  vpn: {
    connection_name: string
    server_address: string
    server_port?: number
    hub_name?: string
    server_certificate?: string
    type: string
    username: string
    credential_ref: string
    split_tunnel: boolean
  }
  ssh: {
    server_address: string
    port: number
    username: string
    auth_method?: SSHAuthMethod
    credential_ref: string
    host_key?: string
  }
  mcp_policy: MCPPolicy
  created_at: string
  updated_at: string
}

export type SaveProfileRequest = {
  profile: ConnectionProfile
  vpn_pre_shared_key: string
  vpn_password: string
  ssh_password: string
  ssh_private_key_path: string
  ssh_private_key_passphrase: string
}

export type TestConnectionRequest = {
  profile: ConnectionProfile
  vpn_password: string
  ssh_password: string
  ssh_private_key_path: string
  ssh_private_key_passphrase: string
}

export type ConnectionTestResult = {
  success: boolean
  kind: 'tunnel' | 'ssh'
  message: string
  ip_address?: string
  tunnel_fingerprint?: string
  ssh_host_key_fingerprint?: string
  duration_ms: number
}

export type TerminalTab = {
  id: string
  profileId: string
  name: string
  closed: boolean
  reason?: string
}

export type UploadSelection = {
  path: string
  name: string
  is_directory: boolean
  size: number
}

export type UploadRequest = {
  profile_id: string
  local_paths: string[]
  remote_directory: string
  overwrite: boolean
	resume: boolean
}

export type UploadState = 'queued' | 'scanning' | 'uploading' | 'completed' | 'failed' | 'cancelled'

export type UploadProgress = {
  job_id: string
  profile_id: string
  state: UploadState
  current_item?: string
  files_total: number
  directories_total: number
  bytes_total: number
  files_completed: number
  directories_completed: number
  bytes_transferred: number
	bytes_resumed: number
	concurrent_files: number
  error_code?: string
  error_message?: string
  started_at_ms: number
  finished_at_ms?: number
}

export type RemoteEntry = {
	name: string
	path: string
	is_directory: boolean
	is_symlink: boolean
	size: number
	mod_time_ms: number
}

export type RemoteDirectory = {
	path: string
	parent: string
	entries: RemoteEntry[]
}

export type DownloadRequest = {
	profile_id: string
	remote_paths: string[]
	local_directory: string
	overwrite: boolean
	resume: boolean
}

export type DownloadState = 'queued' | 'scanning' | 'downloading' | 'completed' | 'failed' | 'cancelled'

export type DownloadProgress = {
	job_id: string
	profile_id: string
	state: DownloadState
	current_item?: string
	files_total: number
	directories_total: number
	bytes_total: number
	files_completed: number
	directories_completed: number
	bytes_transferred: number
	bytes_resumed: number
	concurrent_files: number
	error_code?: string
	error_message?: string
	started_at_ms: number
	finished_at_ms?: number
}

export type AppErrorValue = {
  code: string
  message: string
  stage?: string
  retryable: boolean
  details?: Record<string, unknown>
}
