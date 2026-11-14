"""生成各平台共用的许可证目录和独立许可证压缩包。"""

import argparse
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "LICENSE.txt": "LICENSE",
    "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
    "go-openvpn/LICENSE": "third_party/go-openvpn/LICENSE",
    "go-openvpn/LICENSE_USAGE_EXCEPTION": "third_party/go-openvpn/LICENSE_USAGE_EXCEPTION",
    "go-openvpn/LABREMOTE_CHANGES.md": "third_party/go-openvpn/LABREMOTE_CHANGES.md",
    "go-lzo/LICENSE": "third_party/licenses/go-lzo-LICENSE",
    "atrust/LICENSE": "internal/atrust/protocol/LICENSE",
    "atrust/NOTICE": "internal/atrust/protocol/NOTICE",
    "atrust/MODIFICATIONS.md": "internal/atrust/protocol/MODIFICATIONS.md",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    version = json.loads((ROOT / "wails.json").read_text(encoding="utf-8"))["info"]["productVersion"]
    tag = "v" + version
    for destination, source in FILES.items():
        data = (ROOT / source).read_bytes()
        data.decode("utf-8")
        target = args.output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    instructions = f"""# LabRemote {tag}：许可与重新构建

LabRemote 主程序使用 MIT 许可。内嵌修改后的 go-openvpn 使用 LGPL-2.1-or-later；
aTrust 协议适配使用 Apache-2.0。各组件许可独立适用，完整文本和修改记录见本目录。

完整对应源码（包括宿主、内嵌库、构建脚本及依赖版本）：
https://github.com/EricHongXDD/LabRemote-Go/tree/{tag}
https://github.com/EricHongXDD/LabRemote-Go/archive/refs/tags/{tag}.zip

可以修改 third_party/go-openvpn 中的库代码，并使用源码中的本地 replace 依赖重新链接宿主。
允许为调试这些修改而进行所需的逆向工程。无需专有预编译库或私有链接密钥。

重新构建：安装 .go-version 指定的 Go、Node.js 22 及 README 中对应平台的图形构建依赖，
执行 go install github.com/wailsapp/wails/v2/cmd/wails@v2.13.0，
然后在源码根目录执行 wails build。前端依赖由 frontend/package-lock.json 固定，
Go 依赖由 go.mod / go.sum 固定；Windows 安装包还需要 NSIS。
"""
    (args.output / "REBUILD.md").write_bytes(instructions.encode("utf-8"))
    if args.archive:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.archive, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(args.output.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(args.output).as_posix())
    print(f"许可证目录已生成：{args.output}")


if __name__ == "__main__":
    main()
