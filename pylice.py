"""pylice —— 单文件离线软件授权：Ed25519 签名 + 机器指纹 + 功能位 + 到期 + 心跳宽限。

**零第三方依赖**（自带纯 Python Ed25519，只用标准库），一个文件就能放进任何离线程序：
拷 `pylice.py` 进你的工程，或者 `pip install git+https://github.com/yumoqing/pylice`。

三步用起来：

    # 签发方（一次）：生成密钥对，公钥贴进你的产品代码，私钥留在自己机器
    python pylice.py keygen --app myapp

    # 客户机：报机器码
    python pylice.py machine                       # S1-xxxx-xxxx-xxxx-xx

    # 签发方：出授权
    python pylice.py issue --app myapp --org 某某公司 --days 365 \
        --features pro,export --max-sessions 5 --machine S1-xxxx-... --out 某某公司.lic

    # 客户机：装授权（界面粘贴 / 命令行都行）
    python pylice.py install 某某公司.lic

产品代码里只有这几行：

    from pylice import License
    lic = License(app="myapp", pubkey="<公钥hex>")
    lic.state().label()                     # 给用户看的一句话
    lic.has("export")                       # 功能位
    ok, why = lic.allow("max_sessions", n)  # 数量门禁
    lic.heartbeat_async()                   # 有心跳地址时后台打一次，绝不阻塞启动

不变量（换语言重写也要满足，改这里之前先读）：

- 签名覆盖除 `sig` 外**全部**字段，规范化 JSON（键排序 + 紧凑分隔符 + UTF-8）。
  手改一个字符就验签失败，所以 license 文件不用加密、不用藏。
- 机器指纹三项：系统 UUID / 主网卡 MAC / 系统盘序列号，只存 sha256 前 16 位。
  license 里**留空的位不参与比对**；machine 整体为空 = 不绑机器（任何机器可用）。
- 到期按 **UTC** 当天 23:59:59 算（用 `calendar.timegm`，不要用 `time.mktime`：后者按本机时区
  解释，UTC+8 下会让客户提前一天被锁）。
- 到期 / 宽限用完都**降级**到 `limits` 里能合出来的最小可用（默认 1 个会话），不拒绝启动——
  数据锁死会直接毁掉续费谈判。
- 心跳打不通**不降级**：能否用只由 `last_ok`/`installed_at` + `grace_days` 决定；
  宽限从安装时刻起算，纯内网客户装完必须能正常跑。
- 时钟回拨只做粗检测（记录历史最大值，回退超容差判异常）：抬高"改时间续命"的成本，不是安全边界。
- 时间一律走注入的 `now()`，测试用可推进的 Clock，绝不 sleep 真实天数。
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

__version__ = "1.0.0"

VERSION = 1                                  # license 格式版本
CLOCK_SKEW_TOL = 6 * 3600                    # 允许的时钟回退（秒）
HEARTBEAT_TIMEOUT = 5
TRIAL_DAYS = 30
TRIAL_LIMITS = {"max_sessions": 2}
TRIAL_FEATURES = ("base",)

LICENSE_NAME = "license.lic"
STATE_NAME = "license_state.json"


# =========================================================================== #
# Ed25519（RFC 8032 参考实现，纯 Python；验证 ~10ms，够启动时用一次）
# =========================================================================== #
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_By = 4 * _inv(5) % _P
_Bx = _recover_x(_By, 0)
_B = (_Bx % _P, _By % _P, 1, _Bx * _By % _P)          # 基点（扩展坐标）


def _point_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p, q) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _point_compress(p) -> bytes:
    zinv = _inv(p[2])
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand(seed: bytes) -> Tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 私钥必须是 32 字节")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    """私钥（32 字节 seed）→ 公钥（32 字节）。"""
    a, _ = _expand(seed)
    return _point_compress(_point_mul(a, _B))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _point_compress(_point_mul(a, _B))
    r = int.from_bytes(_sha512(prefix + msg), "little") % _L
    big_r = _point_compress(_point_mul(r, _B))
    h = int.from_bytes(_sha512(big_r + pub + msg), "little") % _L
    s = (r + h * a) % _L
    return big_r + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a_pt = _point_decompress(pub)
    if a_pt is None:
        return False
    r_pt = _point_decompress(sig[:32])
    if r_pt is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:                                  # 拒绝可塑性签名
        return False
    h = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % _L
    return _point_equal(_point_mul(s, _B), _point_add(r_pt, _point_mul(h, a_pt)))


def new_keypair() -> Tuple[bytes, bytes]:
    """生成 (私钥 seed, 公钥)。私钥就是 32 字节随机数。"""
    seed = os.urandom(32)
    return seed, public_key(seed)


# =========================================================================== #
# 签名口径
# =========================================================================== #
def canonical(payload: Dict) -> bytes:
    """签名口径：除 sig 外全部字段，键排序、紧凑分隔符、UTF-8。改口径 = 旧授权全废。"""
    body = {k: v for k, v in payload.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_payload(seed: bytes, payload: Dict) -> str:
    return base64.b64encode(ed25519_sign(seed, canonical(payload))).decode("ascii")


def verify_signature(payload: Dict, sig_b64: str, pubkey_hex: str) -> bool:
    try:
        return ed25519_verify(bytes.fromhex(pubkey_hex or ""), canonical(payload),
                              base64.b64decode(sig_b64 or ""))
    except Exception:                                   # noqa: BLE001
        return False


def load_private_key(path: str) -> bytes:
    """私钥文件 = 32 字节 hex 一行（keygen 生成，权限 600，绝不入仓库）。"""
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


def public_hex(seed: bytes) -> str:
    return public_key(seed).hex()


# =========================================================================== #
# 机器指纹
# =========================================================================== #
def _sha16(value: str) -> str:
    return hashlib.sha256(("pylice|%s" % value).encode("utf-8")).hexdigest()[:16]


def _reg(path: str, name: str) -> str:
    if not sys.platform.startswith("win"):
        return ""
    try:
        import winreg                                   # noqa: PLC0415
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return str(winreg.QueryValueEx(k, name)[0] or "").strip()
    except Exception:                                   # noqa: BLE001
        return ""


def _win_disk() -> str:
    """系统盘序列号：读注册表 Disk\\Enum 的 0 项（wmic 在 Win11 24H2 已删，powershell 太慢）。"""
    return _reg(r"SYSTEM\CurrentControlSet\Services\Disk\Enum", "0")


def _linux_disk() -> str:
    import glob
    for pat in ("/sys/block/sd*/device/serial", "/sys/block/nvme*/device/serial",
                "/sys/block/vd*/serial"):
        for p in sorted(glob.glob(pat)):
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    v = fh.read().strip()
                if v:
                    return v
            except OSError:
                continue
    return ""


def _mac_hw() -> Tuple[str, str]:
    """macOS：ioreg 一次拿到硬件 UUID 与整机序列号。"""
    import subprocess
    try:
        out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:                                   # noqa: BLE001
        return "", ""

    def grab(key: str) -> str:
        for line in out.splitlines():
            if key in line and "=" in line:
                return line.split("=", 1)[1].strip().strip('"')
        return ""
    return grab("IOPlatformUUID"), grab("IOPlatformSerialNumber")


def machine_components() -> Dict[str, str]:
    """原始三项（sys/mac/disk）。取不到给空串，不抛异常。"""
    sysid = disk = ""
    if sys.platform.startswith("win"):
        sysid = _reg(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        disk = _win_disk()
    elif sys.platform == "darwin":
        sysid, disk = _mac_hw()
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    sysid = fh.read().strip()
                if sysid:
                    break
            except OSError:
                continue
        disk = _linux_disk()
    try:
        mac = "%012x" % uuid.getnode()
    except Exception:                                   # noqa: BLE001
        mac = ""
    return {"sys": sysid, "mac": mac, "disk": disk}


def machine_fingerprint(comps: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """哈希后的三项，可直接写进 license；取不到的位是空串。"""
    c = comps if comps is not None else machine_components()
    return {k: (_sha16(v) if v else "") for k, v in c.items()}


def _code_checksum(g: str, m: str, d: str) -> str:
    return hashlib.sha256(("%s:%s:%s" % (g, m, d)).encode()).hexdigest()[:2]


def machine_code(comps: Optional[Dict[str, str]] = None) -> str:
    """给人抄的机器码：S1-<sys>-<mac>-<disk>-<ck>，空位补 0，末两位校验防抄错。"""
    fp = machine_fingerprint(comps)
    g, m, d = (fp["sys"] or "0" * 16), (fp["mac"] or "0" * 16), (fp["disk"] or "0" * 16)
    return "S1-%s-%s-%s-%s" % (g, m, d, _code_checksum(g, m, d))


def parse_machine_code(code: str) -> Dict[str, str]:
    parts = [p.strip() for p in str(code or "").strip().replace(" ", "").split("-")]
    if len(parts) != 5 or parts[0].upper() != "S1":
        raise ValueError("机器码格式不对，应为 S1-16位-16位-16位-2位")
    g, m, d, ck = (p.lower() for p in parts[1:])
    for v in (g, m, d):
        if len(v) != 16:
            raise ValueError("机器码每组应为 16 位十六进制")
    if _code_checksum(g, m, d) != ck:
        raise ValueError("机器码校验位不对（可能抄错）")
    return {"sys": "" if g == "0" * 16 else g,
            "mac": "" if m == "0" * 16 else m,
            "disk": "" if d == "0" * 16 else d}


def fingerprint_match(lic_fp: Dict[str, str], cur_fp: Dict[str, str]) -> Tuple[bool, int]:
    """license 里出现的每一项都要对上；留空的位不参与比对。返回 (是否匹配, 命中数)。"""
    known = [k for k in ("sys", "mac", "disk") if (lic_fp or {}).get(k)]
    if not known:
        return False, 0
    hit = sum(1 for k in known if (cur_fp or {}).get(k) == lic_fp[k])
    return hit == len(known), hit


# =========================================================================== #
# 签发
# =========================================================================== #
def issue(seed: bytes, app: str, org: str = "", days: Optional[int] = None,
          expire: str = "", features=(), limits: Optional[Dict] = None,
          machine: Optional[Dict[str, str]] = None, heartbeat: Optional[Dict] = None,
          license_id: str = "", issued_at: Optional[float] = None) -> Dict:
    """签发一份 license（dict）。machine 传 parse_machine_code() 结果 = 绑单机。"""
    now = time.time() if issued_at is None else float(issued_at)
    if not expire:
        expire = time.strftime("%Y-%m-%d", time.gmtime(now + int(days or 365) * 86400))
    payload = {
        "v": VERSION,
        "app": str(app or ""),
        "id": license_id or "L%s" % time.strftime("%Y%m%d%H%M%S", time.gmtime(now)),
        "org": str(org or ""),
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expire": str(expire),
        "features": sorted({str(f) for f in (features or ())}),
        "limits": {str(k): int(v) for k, v in (limits or {}).items()},
        "machine": dict(machine or {}),
        "heartbeat": dict(heartbeat or {}),
    }
    payload["sig"] = sign_payload(seed, payload)
    return payload


def _parse_expire(text: str) -> Optional[float]:
    """到期日 = UTC 当天 23:59:59（客户看到的是"当天还能用"）。

    必须用 calendar.timegm：time.mktime 按本机时区解释，UTC+8 下到期时刻偏 8~16 小时。
    """
    s = str(text or "").strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            t = time.strptime(s, fmt)
            return float(calendar.timegm(t) + (86399 if len(s) == 10 else 0))
        except ValueError:
            continue
    return None


def check_license(data: Optional[Dict], pubkey_hex: str, app: str = "",
                  machine: Optional[Dict[str, str]] = None, revoked=(),
                  now: Optional[float] = None) -> Tuple[bool, str]:
    """服务端/心跳校验：签名 → 归属 → 吊销 → 到期 → 指纹。返回 (ok, 原因)。"""
    if not data:
        return False, "未签发的授权号"
    if str(data.get("id")) in {str(r) for r in revoked or ()}:
        return False, "授权已吊销"
    if not verify_signature(data, data.get("sig", ""), pubkey_hex):
        return False, "签名校验失败"
    if app and data.get("app") not in (None, app):
        return False, "授权不属于本产品"
    exp = _parse_expire(str(data.get("expire") or ""))
    if exp is None:
        return False, "到期日无效"
    if float(now if now is not None else time.time()) > exp:
        return False, "授权已到期"
    fp = data.get("machine") or {}
    if fp:
        ok, hit = fingerprint_match(fp, machine if machine is not None else machine_fingerprint())
        if not ok:
            return False, "机器指纹不匹配（命中 %d 项）" % hit
    return True, "ok"


# =========================================================================== #
# 路径
# =========================================================================== #
def user_config_dir(app: str) -> str:
    """各平台用户配置目录：%APPDATA%/<app> · ~/Library/Application Support/<app> · ~/.config/<app>。"""
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    elif sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = os.path.join(base, app)
    os.makedirs(d, exist_ok=True)
    return d


# =========================================================================== #
# 状态
# =========================================================================== #
@dataclass
class State:
    mode: str = "invalid"     # trial|licensed|grace|expired|grace_expired|machine_mismatch|invalid|clock_tampered
    ok: bool = False
    reason: str = ""
    org: str = ""
    license_id: str = ""
    expire: str = ""
    features: Set[str] = field(default_factory=set)
    limits: Dict[str, int] = field(default_factory=dict)
    days_left: Optional[int] = None          # 试用/授权剩余天
    offline_days_left: Optional[int] = None  # 心跳宽限剩余天

    def label(self) -> str:
        """给最终用户看的一句话（界面/状态栏直接用）。"""
        if self.mode == "licensed":
            return "已授权：%s · %s 到期" % (self.org or "客户", self.expire)
        if self.mode == "grace":
            return "已授权：%s · %s 到期（%d 天未联网，宽限剩 %d 天）" % (
                self.org or "客户", self.expire,
                self.limits.get("_offline_days", 0), self.offline_days_left or 0)
        if self.mode == "trial":
            return "试用版 · 剩 %d 天 · 最多 %d 个会话" % (
                self.days_left or 0, self.limits.get("max_sessions", 0))
        if self.mode == "expired":
            return "授权已到期（%s）" % (self.expire or "试用期结束")
        if self.mode == "grace_expired":
            return "授权已到期：%d 天未连上授权服务器（宽限 %d 天已用完）" % (
                self.limits.get("_offline_days", 0), self.limits.get("_grace_days", 0))
        if self.mode == "machine_mismatch":
            return "授权与本机不匹配：%s" % (self.reason or "机器码不同")
        if self.mode == "clock_tampered":
            return "系统时间异常（已回拨），请校正时间后重启"
        return "授权无效：%s" % (self.reason or "验签失败")


class License:
    """一个产品 = 一个 License 实例。时间可注入 now()，测试不用 sleep。"""

    def __init__(self, app: str, pubkey: str, path: Optional[str] = None,
                 state_path: Optional[str] = None,
                 now: Optional[Callable[[], float]] = None,
                 trial_days: int = TRIAL_DAYS,
                 trial_limits: Optional[Dict] = None,
                 trial_features=TRIAL_FEATURES,
                 config_dir: Optional[str] = None):
        self.app = str(app or "")
        self.pubkey = pubkey or ""
        base = config_dir or os.environ.get("PYLICE_CONFIG_DIR") or user_config_dir(self.app)
        self.path = path or os.environ.get("PYLICE_LICENSE_FILE") or \
            os.path.join(base, LICENSE_NAME)
        self.state_path = state_path or os.environ.get("PYLICE_STATE_FILE") or \
            os.path.join(base, STATE_NAME)
        self._now = now or time.time
        self.trial_days = int(trial_days)
        self.trial_limits = dict(TRIAL_LIMITS if trial_limits is None else trial_limits)
        self.trial_features = set(trial_features or ())
        self._data: Optional[Dict] = None
        self._state = self._load_state()
        self._cached: Optional[State] = None

    # ---- 文件 ----
    def _load_state(self) -> Dict:
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                raw = json.load(fh)
            return raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    @property
    def data(self) -> Optional[Dict]:
        if self._data is None:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                self._data = raw if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                self._data = {}
        return self._data or None

    def install(self, text: str) -> State:
        """落盘并重算状态（界面「粘贴授权」直接调它）。"""
        obj = json.loads(text) if isinstance(text, str) else dict(text)
        if not isinstance(obj, dict):
            raise ValueError("授权内容不是 JSON 对象")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
        self._data = None
        self._cached = None
        return self.state(refresh=True)

    def install_file(self, path: str) -> State:
        with open(path, encoding="utf-8") as fh:
            return self.install(fh.read())

    # ---- 判定 ----
    def state(self, refresh: bool = False) -> State:
        if self._cached is not None and not refresh:
            return self._cached
        self._cached = self._evaluate()
        return self._cached

    def _touch_clock(self, now: float) -> bool:
        self._state.setdefault("first_seen", int(now))
        seen = int(self._state.get("max_seen") or 0)
        if now > seen + 60:
            self._state["max_seen"] = int(now)
            self._save_state()
        return now < seen - CLOCK_SKEW_TOL

    def _evaluate(self) -> State:
        now = float(self._now())
        rolled_back = self._touch_clock(now)
        data = self.data

        if data is None:                                    # 无授权文件 = 试用
            first = int(self._state.get("first_seen") or now)
            limits = dict(self.trial_limits)
            if rolled_back:
                return State(mode="clock_tampered", ok=False, reason="系统时间被回拨",
                             limits=limits)
            left = self.trial_days - int((now - first) // 86400)
            if left <= 0:
                limits["max_sessions"] = 1                  # 到期仍给 1 个会话取数据
                return State(mode="expired", ok=False, reason="试用期已结束",
                             limits=limits, days_left=0)
            return State(mode="trial", ok=True, features=set(self.trial_features),
                         limits=limits, days_left=left)

        if not verify_signature(data, data.get("sig", ""), self.pubkey):
            return State(mode="invalid", ok=False, reason="签名校验失败")
        if self.app and data.get("app") not in (None, self.app):
            return State(mode="invalid", ok=False, reason="授权不属于本产品")

        base = State(mode="licensed", ok=True, org=str(data.get("org") or ""),
                     license_id=str(data.get("id") or ""),
                     expire=str(data.get("expire") or ""),
                     features=set(data.get("features") or []),
                     limits={k: int(v) for k, v in (data.get("limits") or {}).items()})

        if rolled_back:
            base.mode, base.ok, base.reason = "clock_tampered", False, "系统时间被回拨"
            return base

        fp = data.get("machine") or {}
        if fp:                                              # 空 = 不绑机器
            ok, hit = fingerprint_match(fp, machine_fingerprint())
            if not ok:
                base.mode, base.ok = "machine_mismatch", False
                base.reason = "关键指纹只命中 %d 项" % hit
                return base

        exp_ts = _parse_expire(base.expire)
        if exp_ts is None:
            base.mode, base.ok, base.reason = "invalid", False, "到期日格式不对"
            return base
        if now > exp_ts:
            base.mode, base.ok, base.days_left = "expired", False, 0
            base.limits["max_sessions"] = 1
            return base
        base.days_left = int((exp_ts - now) // 86400)

        if self._state.get("license_id") != base.license_id:    # 换授权文件 → 重算宽限起点
            self._state.update({"license_id": base.license_id,
                                "installed_at": int(now), "last_ok": 0})
            self._save_state()

        hb = data.get("heartbeat") or {}
        url = str(hb.get("url") or "")
        if not url:
            return base                                      # 纯离线授权：到期才失效
        grace = int(hb.get("grace_days") or 15)
        interval = int(hb.get("interval_days") or 7)
        anchor = max(int(self._state.get("last_ok") or 0),
                     int(self._state.get("installed_at") or now))
        offline_s = max(0, int(now - anchor))
        base.limits["_offline_days"] = offline_s // 86400
        base.limits["_grace_days"] = grace
        if offline_s > grace * 86400:
            base.mode, base.ok, base.offline_days_left = "grace_expired", False, 0
            base.limits["max_sessions"] = 1
            return base
        base.offline_days_left = max(0, grace - offline_s // 86400)
        if offline_s > interval * 86400:
            base.mode = "grace"                              # 照常可用，界面提示该联网
        return base

    # ---- 取值 ----
    def has(self, feature: str) -> bool:
        st = self.state()
        return bool(st.ok and ("*" in st.features or feature in st.features))

    def limit(self, name: str, default: Optional[int] = None) -> Optional[int]:
        """授权里的数量上限；没有该字段 = 不限（返回 default）。"""
        return self.state().limits.get(name, default)

    def allow(self, name: str, current: int) -> Tuple[bool, str]:
        """数量门禁：current >= 上限 → (False, 一句能直接显示的理由)。"""
        cap = self.limit(name)
        if not cap or cap <= 0:
            return True, ""
        if current < cap:
            return True, ""
        return False, "当前授权最多 %d 个（%s），需要更多请升级授权" % (cap, name)

    def machine_code(self) -> str:
        return machine_code()

    # ---- 心跳 ----
    def heartbeat(self, url: str = "", timeout: int = HEARTBEAT_TIMEOUT) -> Dict:
        """打一次心跳。打不通只记次数、不降级（降级只看宽限期）。"""
        import urllib.request
        data = self.data or {}
        target = url or str((data.get("heartbeat") or {}).get("url") or "")
        if not target:
            return {"ok": False, "error": "授权没有配置心跳地址"}
        body = json.dumps({"app": self.app, "license_id": data.get("id", ""),
                           "org": data.get("org", ""),
                           "machine": machine_fingerprint(),
                           "ts": int(self._now())}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(target, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        import urllib.error
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
            info = json.loads(raw) if raw.strip().startswith("{") else {}
        except urllib.error.HTTPError as e:
            # 4xx/5xx 也带 JSON 理由（吊销/到期/指纹不符）——要把它显示给用户，别只报状态码
            try:
                raw = e.read().decode("utf-8", "replace")
                info = json.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:                                # noqa: BLE001
                info = {}
            self._state["hb_fail"] = int(self._state.get("hb_fail") or 0) + 1
            self._save_state()
            return {"ok": False, "status": e.code,
                    "error": str(info.get("error") or "HTTP %s" % e.code), "body": info}
        except Exception as e:                               # noqa: BLE001
            self._state["hb_fail"] = int(self._state.get("hb_fail") or 0) + 1
            self._save_state()
            return {"ok": False, "error": str(e)[:200]}
        if info.get("ok") is False:
            return {"ok": False, "error": str(info.get("error") or "被授权服务器拒绝"),
                    "body": info}
        self._state.update({"last_ok": int(float(self._now())), "hb_fail": 0})
        self._save_state()
        self._cached = None
        return {"ok": True, "body": info}

    def heartbeat_async(self, url: str = "", timeout: int = HEARTBEAT_TIMEOUT):
        """后台线程打心跳，绝不阻塞界面启动。"""
        import threading
        t = threading.Thread(target=lambda: self.heartbeat(url, timeout),
                             name="pylice-heartbeat", daemon=True)
        t.start()
        return t


# =========================================================================== #
# 命令行（产品可以直接复用：main(argv, app=..., pubkey=...)）
# =========================================================================== #
def default_key_path() -> str:
    return os.environ.get("PYLICE_ISSUER_KEY") or \
        os.path.join(os.path.expanduser("~"), ".pylice", "issuer_ed25519.key")


def _cmd_keygen(a, app: str) -> int:
    path = a.key or default_key_path()
    if os.path.exists(path) and not a.force:
        print("已存在：%s（要换用 --force；换完所有旧授权失效）" % path)
        print("公钥：%s" % public_hex(load_private_key(path)))
        return 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    seed = os.urandom(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(seed.hex())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print("私钥已写入：%s（备份好，丢了只能换公钥重发全部授权）" % path)
    print("公钥（写进产品的 PUBKEY_HEX）：")
    print(public_hex(seed))
    return 0


def _cmd_machine(a, app: str) -> int:
    print("机器码：%s" % machine_code())
    for k, v in machine_components().items():
        print("  %-4s %s" % (k, (v[:8] + "…" + v[-4:]) if len(v) > 12 else (v or "（取不到）")))
    return 0


def _cmd_issue(a, app: str) -> int:
    seed = load_private_key(a.key or default_key_path())
    machine: Dict[str, str] = {}
    if a.machine:
        try:
            machine = parse_machine_code(a.machine)
        except ValueError as e:
            print("机器码不对：%s" % e)
            return 2
    limits = {"max_sessions": int(a.max_sessions)} if a.max_sessions else {}
    hb = {"url": a.heartbeat, "interval_days": int(a.interval),
          "grace_days": int(a.grace)} if a.heartbeat else {}
    lic = issue(seed, app=a.app or app, org=a.org, days=a.days, expire=a.expire,
                features=[s.strip() for s in (a.features or "").split(",") if s.strip()],
                limits=limits, machine=machine, heartbeat=hb, license_id=a.id)
    out = a.out or "%s.lic" % (a.org or lic["id"])
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(lic, fh, ensure_ascii=False, indent=1)
    print("已签发：%s" % os.path.abspath(out))
    print("  %s / %s / 到期 %s / 功能位 %s / 限额 %s" % (
        lic["id"], lic["org"], lic["expire"],
        ",".join(lic["features"]) or "-", lic["limits"] or "-"))
    print("  绑定机器：%s" % (", ".join("%s=%s" % (k, v[:8]) for k, v in machine.items())
                              if machine else "否（任何机器可用）"))
    return 0


def _cmd_install(a, app: str) -> int:
    if not a.pubkey:
        print("需要 --pubkey（产品内嵌的公钥）才能验签")
        return 2
    lic = License(app=a.app or app, pubkey=a.pubkey, path=a.license or None,
                  state_path=a.state or None)
    st = lic.install_file(a.file)
    print("授权文件：%s" % lic.path)
    print("状态：%s [%s]" % (st.label(), st.mode))
    return 0 if st.ok else 1


def _cmd_verify(a, app: str) -> int:
    pubkey = a.pubkey
    if not pubkey:
        print("需要 --pubkey（产品内嵌的公钥）")
        return 2
    lic = License(app=a.app or app, pubkey=pubkey, path=a.file,
                  state_path=a.state or os.path.join(os.path.dirname(os.path.abspath(a.file)),
                                                     STATE_NAME))
    st = lic.state(refresh=True)
    print("机器码：%s" % lic.machine_code())
    print("状态  ：%s [%s]" % (st.label(), st.mode))
    print("原因  ：%s" % (st.reason or "-"))
    print("功能位：%s" % (", ".join(sorted(st.features)) or "-"))
    print("限额  ：%s" % (", ".join("%s=%s" % kv for kv in sorted(st.limits.items())) or "-"))
    return 0 if st.ok else 1


def _cmd_inspect(a, app: str) -> int:
    with open(a.file, encoding="utf-8") as fh:
        d = json.load(fh)
    ok = verify_signature(d, d.get("sig", ""), a.pubkey) if a.pubkey else None
    print("签名：%s" % ("✅ 通过" if ok else ("❌ 失败" if ok is False else "（未给 --pubkey，跳过）")))
    for k in ("id", "app", "org", "issued_at", "expire", "features", "limits", "heartbeat"):
        print("  %-9s %s" % (k, d.get(k)))
    m = d.get("machine") or {}
    print("  machine   %s" % (", ".join("%s=%s" % (k, (v or "-")[:8])
                                        for k, v in sorted(m.items()))
                              if m else "（不绑机器）"))
    return 0 if ok is not False else 1


def _cmd_serve(a, app: str) -> int:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    if not a.pubkey:
        print("需要 --pubkey（产品内嵌的公钥）")
        return 2
    directory = a.dir
    os.makedirs(directory, exist_ok=True)
    revoked = {s.strip() for s in (a.revoke or "").split(",") if s.strip()}
    cache = {"t": 0.0, "lic": {}}

    def load_all() -> Dict[str, Dict]:
        out = {}
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".lic"):
                continue
            try:
                with open(os.path.join(directory, name), encoding="utf-8") as fh:
                    d = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(d, dict) and d.get("id"):
                out[str(d["id"])] = d
        return out

    class H(BaseHTTPRequestHandler):
        def _json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):                                  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json(400, {"ok": False, "error": "请求不是 JSON"})
            if cache["t"] < time.time() - 30:
                cache["lic"], cache["t"] = load_all(), time.time()
            d = cache["lic"].get(str(req.get("license_id") or ""))
            ok, why = check_license(d, a.pubkey, app=a.app or app,
                                    machine=req.get("machine") or {}, revoked=revoked)
            if not ok:
                if not a.quiet:
                    print("[hb] 拒绝 %s：%s" % (req.get("license_id"), why))
                return self._json(403, {"ok": False, "error": why})
            return self._json(200, {"ok": True, "expire": d.get("expire"),
                                    "server_time": int(time.time())})

        def do_GET(self):                                   # noqa: N802
            self._json(200, {"ok": True, "service": "pylice",
                             "licenses": len(load_all())})

        def log_message(self, format, *args):               # noqa: A002
            pass

    srv = ThreadingHTTPServer((a.host, a.port), H)
    if not a.quiet:
        print("授权服务：http://%s:%d/hb（%s，%d 份授权在位）"
              % (a.host, srv.server_address[1], os.path.abspath(directory),
                 len(load_all())))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: Optional[List[str]] = None, app: str = "", pubkey: str = "",
         key: str = "") -> int:
    """命令行入口。产品可以钉默认值：main(app="myapp", pubkey="<hex>")。"""
    import argparse
    p = argparse.ArgumentParser(prog="pylice", description="单文件离线软件授权")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="生成签发密钥（私钥在仓库外）")
    k.add_argument("--key", default=key)
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=_cmd_keygen)

    m = sub.add_parser("machine", help="打印本机机器码")
    m.set_defaults(fn=_cmd_machine)

    i = sub.add_parser("issue", help="签发 license")
    i.add_argument("--app", default=app)
    i.add_argument("--org", default="")
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--expire", default="", help="YYYY-MM-DD，优先于 --days")
    i.add_argument("--features", default="")
    i.add_argument("--max-sessions", dest="max_sessions", type=int, default=0)
    i.add_argument("--machine", default="", help="客户机器码（不传=不绑机器）")
    i.add_argument("--heartbeat", default="", help="心跳地址，如 https://x/hb")
    i.add_argument("--interval", type=int, default=7)
    i.add_argument("--grace", type=int, default=15)
    i.add_argument("--id", default="")
    i.add_argument("--key", default=key)
    i.add_argument("--out", default="")
    i.set_defaults(fn=_cmd_issue)

    ins = sub.add_parser("install", help="安装授权文件")
    ins.add_argument("file")
    ins.add_argument("--app", default=app)
    ins.add_argument("--pubkey", default=pubkey)
    ins.add_argument("--license", default="", help="落盘路径（默认按产品配置目录）")
    ins.add_argument("--state", default="")
    ins.set_defaults(fn=_cmd_install)

    v = sub.add_parser("verify", help="在本机核验授权")
    v.add_argument("file")
    v.add_argument("--app", default=app)
    v.add_argument("--pubkey", default=pubkey)
    v.add_argument("--state", default="")
    v.set_defaults(fn=_cmd_verify)

    s = sub.add_parser("inspect", help="只看内容与签名（不校验本机）")
    s.add_argument("file")
    s.add_argument("--pubkey", default=pubkey)
    s.set_defaults(fn=_cmd_inspect)

    sv = sub.add_parser("serve", help="心跳+吊销服务")
    sv.add_argument("--dir", default="licenses")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--app", default=app)
    sv.add_argument("--pubkey", default=pubkey)
    sv.add_argument("--revoke", default="", help="吊销的授权号，逗号分隔")
    sv.add_argument("--quiet", action="store_true")
    sv.set_defaults(fn=_cmd_serve)

    a = p.parse_args(argv)
    return a.fn(a, app)


if __name__ == "__main__":
    sys.exit(main())