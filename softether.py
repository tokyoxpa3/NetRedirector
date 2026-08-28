"""SoftEther VPN Client vpncmd.exe wrapper.

Handles the Simplified Chinese build's GBK (cp936) output encoding and
provides typed helpers around the vpncmd client commands we need.

Usage:
    from softether import SoftEtherClient
    se = SoftEtherClient()
    print(se.nic_list())
    se.account_set("VPN12", "1.2.3.4", 443)
    se.account_connect("VPN12")
    print(se.account_status("VPN12"))
"""

import re
import subprocess

import vpngate_config as config

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SoftEtherError(RuntimeError):
    pass


# vpncmd error codes that are benign (not fatal) for our workflow.
# 37 = "specified setting is not connected" -> returned by AccountStatusGet
#      for an offline account. We treat it as "not connected", not an error.
_BENIGN_CODES = frozenset({37})


class SoftEtherClient:
    def __init__(self, vpncmd_path: str = config.VPNCMD_PATH):
        self.vpncmd_path = vpncmd_path

    def run(self, *args: str) -> str:
        """Run a vpncmd client-mode command and return decoded output.

        IMPORTANT: pass the command tokens as separate, UNQUOTED args. vpncmd
        fails (""<cmd>": 命令未找到") when the command is wrapped in quotes.
        """
        cmd = [self.vpncmd_path, "/client", "localhost", "/cmd", *args]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
            creationflags=_CREATE_NO_WINDOW,
        )
        out = proc.stdout.decode(config.VPNCMD_ENCODING, errors="replace")
        if (
            proc.returncode != 0
            and "命令成功完成" not in out
            and proc.returncode not in _BENIGN_CODES
        ):
            # Many "errors" (e.g. disconnect-when-offline) still return 0-ish;
            # surface fatal failures only.
            raise SoftEtherError(
                f"vpncmd failed rc={proc.returncode}: {out[-300:]}"
            )
        return out

    def check_success(self, out: str) -> bool:
        return "命令成功完成" in out

    # ----- queries -----
    def nic_list(self) -> list[str]:
        out = self.run("NicList")
        names = []
        for line in out.splitlines():
            if line.startswith("虚拟网络适配器名|"):
                names.append(line.split("|", 1)[1].strip())
        return names

    def account_list(self) -> list[str]:
        out = self.run("AccountList")
        names = []
        for line in out.splitlines():
            if line.startswith("VPN 连接设置名称"):
                names.append(line.split("|", 1)[1].strip())
        return names

    def account_servers(self) -> dict[str, tuple[str, int]]:
        """單次 AccountList 解析出 虛擬網卡名 -> (host, port)。

        AccountList 的輸出已含每個帳號的 server 主機/埠 (欄位
        「VPN Server 主机名(地址)」) 與對應的虛擬網卡名，故不需要
        再對每個帳號個別呼叫 AccountGet，可將 refresh 的 vpncmd
        子程序呼叫數從 2+N 降到 2。
        """
        out = self.run("AccountList")
        mapping: dict[str, tuple[str, int]] = {}
        ip_port = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
        pending_server = None
        for line in out.splitlines():
            if "|" not in line:
                continue
            key, _, val = line.partition("|")
            key = key.strip()
            val = val.strip()
            if key.startswith("VPN Server 主机名"):
                m = ip_port.match(val)
                if m:
                    pending_server = (m.group(1), int(m.group(2)))
            elif key.startswith("虚拟网络适配器名") and pending_server:
                mapping[val] = pending_server
                pending_server = None
        return mapping

    def account_status(self, name: str) -> dict:
        """Return parsed AccountStatusGet fields."""
        out = self.run("AccountStatusGet", name)
        status = {"raw": out}
        for line in out.splitlines():
            if "|" not in line:
                continue
            key, _, val = line.partition("|")
            key = key.strip()
            val = val.strip()
            if key and val:
                status[key] = val
        return status

    def account_get(self, name: str) -> dict:
        out = self.run("AccountGet", name)
        info = {"raw": out}
        for line in out.splitlines():
            if "|" not in line:
                continue
            key, _, val = line.partition("|")
            key = key.strip()
            val = val.strip()
            if key and val:
                info[key] = val
        return info

    # ----- actions -----
    def account_set(self, name: str, host: str, port: int, hub: str = config.VPNGATE_HUB) -> str:
        if name not in self.account_list():
            return self.run(
                "AccountCreate", name,
                f"/SERVER:{host}:{port}",
                f"/HUB:{hub}",
                f"/USERNAME:{config.VPNGATE_USERNAME}",
                f"/NICNAME:{name}",
            )
        return self.run(
            "AccountSet", name,
            f"/SERVER:{host}:{port}",
            f"/HUB:{hub}",
        )

    def account_set_anonymous(self, name: str) -> str:
        self.run("AccountUsernameSet", name, f"/USERNAME:{config.VPNGATE_USERNAME}")
        return self.run("AccountAnonymousSet", name)

    def account_connect(self, name: str) -> str:
        return self.run("AccountConnect", name)

    def account_disconnect(self, name: str) -> str:
        try:
            return self.run("AccountDisconnect", name)
        except SoftEtherError:
            # Error 37 ("specified setting is not connected") is benign.
            return ""

    def is_connected(self, name: str) -> bool:
        s = self.account_status(name)
        return "连接完成" in s.get("会话状态", "")

    def account_server(self, name: str) -> tuple[str, int] | None:
        """Return (host, port) the account points at, or None if unavailable."""
        info = self.account_get(name)
        host = info.get("目标 VPN Server 主机名", "").strip()
        port_s = info.get("目标 VPN Server 端口号", "").strip()
        if not host:
            return None
        try:
            port = int(port_s)
        except ValueError:
            port = 0
        return host, port