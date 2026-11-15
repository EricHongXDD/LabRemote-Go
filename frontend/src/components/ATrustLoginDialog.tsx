export type ATrustChallenge = {id: string; profile_id: string; profile_name: string; server: string; auth_host: string}
type Props = {challenge: ATrustChallenge; onCancel: (id: string) => void}

export default function ATrustLoginDialog({challenge, onCancel}: Props) {
  return <div className="modal-backdrop atrust-auth-backdrop" role="dialog" aria-modal="true" aria-label="aTrust 网页认证">
    <div className="browser-dialog">
      <div className="dialog-titlebar"><div><span className="eyebrow">ISOLATED ATRUST LOGIN</span><h2>aTrust 网页认证</h2></div></div>
      <div className="browser-dialog-body">
        <p>连接：{challenge.profile_name}</p><p>VPN 入口：{challenge.server}</p><p>认证站点：{challenge.auth_host}</p>
        <p role="status">正在等待你在独立浏览器中完成登录及验证码。</p>
        <p>认证后返回应用，仅为配置的 SSH 目标建立通道。若浏览器已在后台打开，请切换至登录窗口。</p>
        <p className="form-note">此窗口使用本次临时浏览器环境，不启动 VPN 客户端，不修改系统路由、DNS 或代理。</p>
      </div>
      <div className="dialog-actions"><button className="button secondary" onClick={() => onCancel(challenge.id)}>取消连接</button></div>
    </div>
  </div>
}
