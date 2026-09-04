"""
config_store.py — 設定序列化與檔案 I/O (自 IntegratedApp.py 抽出)

純邏輯、無 GUI 依賴：代理密碼以 DPAPI 加密存放、規則保存 UI 辨識字串。
"""

import json
import os

import secure_config


def build_config_data(lang, ping_target, minimize_to_tray, hubs, custom_proxies, rules, check_updates=True):
    """把執行期狀態序列化為 config.json 結構。

    - Proxy: 移除動態數據 (latency/ID)，密碼以 DPAPI 加密
    - Rules: 保存 Proxy 的 UI 辨識字串 (例如 "[Custom] MyVPN") 而非動態 ID
    - minimize_to_tray: 關閉視窗時是否縮到系統匣
    - check_updates: 啟動時是否自動檢查更新
    """
    config_data = {
        "lang": lang,
        "ping_target": ping_target,
        "minimize_to_tray": bool(minimize_to_tray),
        "check_updates": bool(check_updates),
        "hubs": hubs or {},
        "proxies": [],
        "rules": [],
    }

    for p in custom_proxies:
        config_data["proxies"].append({
            "name": p['name'],
            "type": p['type'],
            "ip": p['ip'],
            "port": p['port'],
            "user": p['user'],
            "pass": secure_config.encrypt_password(p['pass']),
        })

    for r in rules:
        config_data["rules"].append({
            "type": r['type'],
            "target": r['target'],
            "hosts": r.get('hosts', '*'),
            "ports": r.get('ports', '*'),
            "proto": r.get('proto', 'BOTH'),
            "action": r['action'],
            "action_key": r.get('action_key'),
            "proxy_text": r['proxy'],
            # 穩定識別 (自訂代理名稱或 Hub 端口字串):還原時優先以此反查,
            # 不受顯示文字翻譯/改版影響;舊版設定檔無此欄位時回退 proxy_text
            "proxy_name": r.get('proxy_name', ''),
        })

    return config_data


def save_config_file(path, data):
    """寫入設定檔 (原子性:先寫暫存檔再取代,避免寫入中途當機留下半截檔案)。

    成功回傳 None,失敗回傳錯誤訊息字串。
    """
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        return None
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return str(e)


def load_config_file(path):
    """讀取設定檔。

    - 檔案不存在回傳 None。
    - 內容解析失敗 (非 JSON / 編碼錯誤) 時把氈損檔案改名保留為
      ``<path>.corrupt.bak`` 再回傳 None, 讓後續存檔寫入新檔時不會把
      使用者僅存的資料直接覆蓋掉。
    - 讀取失敗 (OSError: 檔案被防毒/備份軟體短暫鎖住、權限問題) 只回傳
      None, 不動檔案 - 檔案本身可能完好, 誤判成氈損會把好檔搬走。
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        backup_path = path + ".corrupt.bak"
        try:
            if os.path.exists(backup_path):
                os.remove(backup_path)
            os.replace(path, backup_path)
        except OSError:
            pass
        return None
    except OSError:
        return None
