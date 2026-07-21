export namespace app {

	export class ConnectionTestResult {
	    success: boolean;
	    kind: string;
	    message: string;
	    ip_address?: string;
	    tunnel_fingerprint?: string;
	    ssh_host_key_fingerprint?: string;
	    duration_ms: number;

	    static createFrom(source: any = {}) {
	        return new ConnectionTestResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.kind = source["kind"];
	        this.message = source["message"];
	        this.ip_address = source["ip_address"];
	        this.tunnel_fingerprint = source["tunnel_fingerprint"];
	        this.ssh_host_key_fingerprint = source["ssh_host_key_fingerprint"];
	        this.duration_ms = source["duration_ms"];
	    }
	}
	export class SaveProfileRequest {
	    profile: model.ConnectionProfile;
	    vpn_pre_shared_key: string;
	    vpn_password: string;
	    ssh_password: string;
	    ssh_private_key_path: string;
	    ssh_private_key_passphrase: string;

	    static createFrom(source: any = {}) {
	        return new SaveProfileRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile = this.convertValues(source["profile"], model.ConnectionProfile);
	        this.vpn_pre_shared_key = source["vpn_pre_shared_key"];
	        this.vpn_password = source["vpn_password"];
	        this.ssh_password = source["ssh_password"];
	        this.ssh_private_key_path = source["ssh_private_key_path"];
	        this.ssh_private_key_passphrase = source["ssh_private_key_passphrase"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TestConnectionRequest {
	    profile: model.ConnectionProfile;
	    vpn_password: string;
	    ssh_password: string;
	    ssh_private_key_path: string;
	    ssh_private_key_passphrase: string;

	    static createFrom(source: any = {}) {
	        return new TestConnectionRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile = this.convertValues(source["profile"], model.ConnectionProfile);
	        this.vpn_password = source["vpn_password"];
	        this.ssh_password = source["ssh_password"];
	        this.ssh_private_key_path = source["ssh_private_key_path"];
	        this.ssh_private_key_passphrase = source["ssh_private_key_passphrase"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace mcpserver {

	export class Status {
	    enabled: boolean;
	    address: string;
	    port: number;

	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.address = source["address"];
	        this.port = source["port"];
	    }
	}

}

export namespace model {

	export class MCPPolicy {
	    enabled_for_profile: boolean;
	    allow_exec: boolean;
	    allow_interactive: boolean;
	    allow_disconnect: boolean;

	    static createFrom(source: any = {}) {
	        return new MCPPolicy(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled_for_profile = source["enabled_for_profile"];
	        this.allow_exec = source["allow_exec"];
	        this.allow_interactive = source["allow_interactive"];
	        this.allow_disconnect = source["allow_disconnect"];
	    }
	}
	export class SSHConfig {
	    server_address: string;
	    port: number;
	    username: string;
	    auth_method?: string;
	    credential_ref: string;
	    host_key?: string;

	    static createFrom(source: any = {}) {
	        return new SSHConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server_address = source["server_address"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.auth_method = source["auth_method"];
	        this.credential_ref = source["credential_ref"];
	        this.host_key = source["host_key"];
	    }
	}
	export class VPNConfig {
	    connection_name: string;
	    server_address: string;
	    server_port?: number;
	    hub_name?: string;
	    server_certificate?: string;
	    type: string;
	    username: string;
	    credential_ref: string;
	    split_tunnel: boolean;

	    static createFrom(source: any = {}) {
	        return new VPNConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connection_name = source["connection_name"];
	        this.server_address = source["server_address"];
	        this.server_port = source["server_port"];
	        this.hub_name = source["hub_name"];
	        this.server_certificate = source["server_certificate"];
	        this.type = source["type"];
	        this.username = source["username"];
	        this.credential_ref = source["credential_ref"];
	        this.split_tunnel = source["split_tunnel"];
	    }
	}
	export class ConnectionProfile {
	    id: string;
	    display_name: string;
	    group?: string;
	    connection_mode?: string;
	    vpn: VPNConfig;
	    ssh: SSHConfig;
	    mcp_policy: MCPPolicy;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    updated_at: any;

	    static createFrom(source: any = {}) {
	        return new ConnectionProfile(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.display_name = source["display_name"];
	        this.group = source["group"];
	        this.connection_mode = source["connection_mode"];
	        this.vpn = this.convertValues(source["vpn"], VPNConfig);
	        this.ssh = this.convertValues(source["ssh"], SSHConfig);
	        this.mcp_policy = this.convertValues(source["mcp_policy"], MCPPolicy);
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.updated_at = this.convertValues(source["updated_at"], null);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class VPNStatus {
	    profile_id: string;
	    state: string;
	    error_code?: string;
	    ip_address?: string;
	    interface?: string;
	    route_ready: boolean;
	    reference_num: number;
	    // Go type: time
	    updated_at: any;

	    static createFrom(source: any = {}) {
	        return new VPNStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile_id = source["profile_id"];
	        this.state = source["state"];
	        this.error_code = source["error_code"];
	        this.ip_address = source["ip_address"];
	        this.interface = source["interface"];
	        this.route_ready = source["route_ready"];
	        this.reference_num = source["reference_num"];
	        this.updated_at = this.convertValues(source["updated_at"], null);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConnectionStatus {
	    profile_id: string;
	    connection_mode: string;
	    vpn: VPNStatus;
	    ssh_connected: boolean;
	    ui_sessions: number;
	    mcp_sessions: number;
	    active_commands: number;
	    active_transfers: number;
	    browser_sessions: number;

	    static createFrom(source: any = {}) {
	        return new ConnectionStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile_id = source["profile_id"];
	        this.connection_mode = source["connection_mode"];
	        this.vpn = this.convertValues(source["vpn"], VPNStatus);
	        this.ssh_connected = source["ssh_connected"];
	        this.ui_sessions = source["ui_sessions"];
	        this.mcp_sessions = source["mcp_sessions"];
	        this.active_commands = source["active_commands"];
	        this.active_transfers = source["active_transfers"];
	        this.browser_sessions = source["browser_sessions"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DownloadProgress {
	    job_id: string;
	    profile_id: string;
	    state: string;
	    current_item?: string;
	    files_total: number;
	    directories_total: number;
	    bytes_total: number;
	    files_completed: number;
	    directories_completed: number;
	    bytes_transferred: number;
	    bytes_resumed: number;
	    concurrent_files: number;
	    error_code?: string;
	    error_message?: string;
	    started_at_ms: number;
	    finished_at_ms?: number;

	    static createFrom(source: any = {}) {
	        return new DownloadProgress(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.job_id = source["job_id"];
	        this.profile_id = source["profile_id"];
	        this.state = source["state"];
	        this.current_item = source["current_item"];
	        this.files_total = source["files_total"];
	        this.directories_total = source["directories_total"];
	        this.bytes_total = source["bytes_total"];
	        this.files_completed = source["files_completed"];
	        this.directories_completed = source["directories_completed"];
	        this.bytes_transferred = source["bytes_transferred"];
	        this.bytes_resumed = source["bytes_resumed"];
	        this.concurrent_files = source["concurrent_files"];
	        this.error_code = source["error_code"];
	        this.error_message = source["error_message"];
	        this.started_at_ms = source["started_at_ms"];
	        this.finished_at_ms = source["finished_at_ms"];
	    }
	}
	export class DownloadRequest {
	    profile_id: string;
	    remote_paths: string[];
	    local_directory: string;
	    overwrite: boolean;
	    resume: boolean;

	    static createFrom(source: any = {}) {
	        return new DownloadRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile_id = source["profile_id"];
	        this.remote_paths = source["remote_paths"];
	        this.local_directory = source["local_directory"];
	        this.overwrite = source["overwrite"];
	        this.resume = source["resume"];
	    }
	}

	export class RemoteEntry {
	    name: string;
	    path: string;
	    is_directory: boolean;
	    is_symlink: boolean;
	    size: number;
	    mod_time_ms: number;

	    static createFrom(source: any = {}) {
	        return new RemoteEntry(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.is_directory = source["is_directory"];
	        this.is_symlink = source["is_symlink"];
	        this.size = source["size"];
	        this.mod_time_ms = source["mod_time_ms"];
	    }
	}
	export class RemoteDirectory {
	    path: string;
	    parent: string;
	    entries: RemoteEntry[];

	    static createFrom(source: any = {}) {
	        return new RemoteDirectory(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.parent = source["parent"];
	        this.entries = this.convertValues(source["entries"], RemoteEntry);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}


	export class UploadProgress {
	    job_id: string;
	    profile_id: string;
	    state: string;
	    current_item?: string;
	    files_total: number;
	    directories_total: number;
	    bytes_total: number;
	    files_completed: number;
	    directories_completed: number;
	    bytes_transferred: number;
	    bytes_resumed: number;
	    concurrent_files: number;
	    error_code?: string;
	    error_message?: string;
	    started_at_ms: number;
	    finished_at_ms?: number;

	    static createFrom(source: any = {}) {
	        return new UploadProgress(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.job_id = source["job_id"];
	        this.profile_id = source["profile_id"];
	        this.state = source["state"];
	        this.current_item = source["current_item"];
	        this.files_total = source["files_total"];
	        this.directories_total = source["directories_total"];
	        this.bytes_total = source["bytes_total"];
	        this.files_completed = source["files_completed"];
	        this.directories_completed = source["directories_completed"];
	        this.bytes_transferred = source["bytes_transferred"];
	        this.bytes_resumed = source["bytes_resumed"];
	        this.concurrent_files = source["concurrent_files"];
	        this.error_code = source["error_code"];
	        this.error_message = source["error_message"];
	        this.started_at_ms = source["started_at_ms"];
	        this.finished_at_ms = source["finished_at_ms"];
	    }
	}
	export class UploadRequest {
	    profile_id: string;
	    local_paths: string[];
	    remote_directory: string;
	    overwrite: boolean;
	    resume: boolean;

	    static createFrom(source: any = {}) {
	        return new UploadRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile_id = source["profile_id"];
	        this.local_paths = source["local_paths"];
	        this.remote_directory = source["remote_directory"];
	        this.overwrite = source["overwrite"];
	        this.resume = source["resume"];
	    }
	}
	export class UploadSelection {
	    path: string;
	    name: string;
	    is_directory: boolean;
	    size: number;

	    static createFrom(source: any = {}) {
	        return new UploadSelection(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.name = source["name"];
	        this.is_directory = source["is_directory"];
	        this.size = source["size"];
	    }
	}


}
