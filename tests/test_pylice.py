"""pylice 用例：Ed25519（RFC 8032 向量 + 与 cryptography 互验）+ 授权全链路。

用法：python tests/test_pylice.py      （零依赖；装了 cryptography 会多做两组互验）
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pylice as L                                          # noqa: E402

PASS, FAIL = [], []


def check(name, fn):
    t0 = time.time()
    try:
        fn()
        PASS.append(name)
        print("  ✅ %-36s %.2fs" % (name, time.time() - t0))
    except Exception as e:                                  # noqa: BLE001
        FAIL.append((name, str(e)))
        print("  ❌ %-36s %s" % (name, str(e)[:220]))
        traceback.print_exc()


class Clock:
    """可推进的时间源：测到期/宽限不靠 sleep。"""

    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, days: float) -> None:
        self.t += days * 86400


# =========================================================================== #
# Ed25519
# =========================================================================== #
# RFC 8032 §7.1 TEST 1 / TEST 2 / TEST 3
RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def t_rfc_vectors():
    for sk, pk, msg, sig in RFC_VECTORS:
        seed, pub, m, want = (bytes.fromhex(sk), bytes.fromhex(pk),
                             bytes.fromhex(msg), bytes.fromhex(sig))
        assert L.public_key(seed) == pub, "公钥推导不对"
        got = L.ed25519_sign(seed, m)
        assert got == want, "签名与 RFC 8032 向量不一致"
        assert L.ed25519_verify(pub, m, want), "自验失败"
        bad = bytearray(want)
        bad[0] ^= 1
        assert not L.ed25519_verify(pub, m, bytes(bad)), "被改的签名竟然通过"
        assert not L.ed25519_verify(pub, m + b"x", want), "消息被改竟然通过"
        assert not L.ed25519_verify(pub, m, want[:63]), "短签名竟然通过"


def t_cross_cryptography():
    """与 cryptography 互验（装了才跑）：证明纯 Python 实现与主流库一致。"""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception:                                       # noqa: BLE001
        print("     （没装 cryptography，跳过互验）")
        return
    seed = os.urandom(32)
    pub = L.public_key(seed)
    msg = b"cross-check payload"
    # 我签 → cryptography 验
    sig = L.ed25519_sign(seed, msg)
    Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(sig, msg)
    # cryptography 签 → 我验
    other = Ed25519PrivateKey.generate()
    other_pub = other.public_key().public_bytes_raw()
    other_sig = other.sign(msg)
    assert L.ed25519_verify(other_pub, msg, other_sig), "验不了 cryptography 的签名"


def t_canonical_stable():
    a = {"b": 1, "a": [1, 2], "c": {"z": 1, "y": "中文"}}
    b = {"c": {"y": "中文", "z": 1}, "a": [1, 2], "b": 1}
    assert L.canonical(a) == L.canonical(b), "字段顺序不同应等价"
    assert L.canonical({"x": 1, "sig": "zz"}) == L.canonical({"x": 1}), "sig 不该进签名"


# =========================================================================== #
# 授权
# =========================================================================== #
class Env:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="pylice_")
        self.seed, pub = L.new_keypair()
        self.pub = pub.hex()                            # License 收 hex 字符串
        self.clock = Clock()
        self.path = os.path.join(self.dir, "license.lic")
        self.state = os.path.join(self.dir, "state.json")

    def lic(self, **kw) -> L.License:
        kw.setdefault("app", "demo")
        kw.setdefault("pubkey", self.pub)
        kw.setdefault("path", self.path)
        kw.setdefault("state_path", self.state)
        kw.setdefault("now", self.clock)
        return L.License(**kw)

    def issue(self, **kw) -> dict:
        kw.setdefault("app", "demo")
        kw.setdefault("issued_at", self.clock.t)
        kw.setdefault("org", "测试客户")
        return L.issue(self.seed, **kw)

    def write(self, payload: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def with_env(fn):
    def wrap():
        env = Env()
        try:
            fn(env)
        finally:
            env.cleanup()
    return wrap


def _serve(answer='{"ok": true}', status=200):
    hits = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):                                  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            hits.append(json.loads(self.rfile.read(n) or b"{}"))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(answer if isinstance(answer, bytes) else answer.encode("utf-8"))

        def log_message(self, format, *args):               # noqa: A002
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/hb" % srv.server_address[1], hits


def t_machine_code(env):
    code = L.machine_code()
    fp = L.parse_machine_code(code)
    cur = L.machine_fingerprint()
    assert fp == cur, (fp, cur)
    assert L.fingerprint_match(fp, cur)[0]
    try:
        L.parse_machine_code(code[:-2] + ("00" if not code.endswith("00") else "11"))
    except ValueError:
        return
    raise AssertionError("校验位错了却没报错")


def t_roundtrip(env):
    env.write(env.issue(days=365, features=["pro", "export"],
                        limits={"max_sessions": 5}, machine=L.machine_fingerprint()))
    lic = env.lic()
    st = lic.state()
    assert st.mode == "licensed" and st.ok, (st.mode, st.reason)
    assert st.limits["max_sessions"] == 5 and lic.has("pro") and not lic.has("jump")
    assert lic.allow("max_sessions", 4)[0] and not lic.allow("max_sessions", 5)[0]
    assert 360 <= (st.days_left or 0) <= 366


def t_other_machine(env):
    env.write(env.issue(days=30, machine={"sys": "a" * 16, "mac": "b" * 16, "disk": "c" * 16}))
    assert env.lic().state().mode == "machine_mismatch"


def t_partial_fingerprint(env):
    """license 里缺 disk 时，剩两项都得中（换盘要重签）；这两项绝不能当成"任意中一项"。"""
    cur = L.machine_fingerprint()
    part = {"sys": cur["sys"], "mac": cur["mac"], "disk": ""}
    env.write(env.issue(days=30, machine=part))
    assert env.lic().state().ok
    env.write(env.issue(days=30, machine=dict(part, mac="f" * 16)))
    assert env.lic().state().mode == "machine_mismatch"


def t_unbound(env):
    env.write(env.issue(days=30))
    assert env.lic().state().mode == "licensed", "不绑机器的授权必须任何机器可用"


def t_wrong_app(env):
    env.write(env.issue(days=30, app="other-product"))
    st = env.lic().state()
    assert st.mode == "invalid" and "产品" in st.reason, (st.mode, st.reason)


def t_expired(env):
    env.write(env.issue(expire=time.strftime("%Y-%m-%d", time.gmtime(env.clock.t - 2 * 86400)),
                        machine=L.machine_fingerprint()))
    st = env.lic().state()
    assert st.mode == "expired" and not st.ok and st.limits["max_sessions"] == 1, (st.mode, st.limits)


def t_expire_utc(env):
    """到期日按 UTC 当天结束算；本地时区不能让它提前一天锁死。"""
    day = time.strftime("%Y-%m-%d", time.gmtime(env.clock.t))
    env.write(env.issue(expire=day, machine=L.machine_fingerprint()))
    assert env.lic().state().ok, "当天应可用"
    env.clock.t += 86400 + 60
    assert env.lic().state().mode == "expired"


def t_tampered(env):
    d = env.issue(days=365, machine=L.machine_fingerprint())
    d["expire"] = "2099-12-31"
    env.write(d)
    st = env.lic().state()
    assert st.mode == "invalid" and not st.ok, (st.mode, st.reason)


def t_sig_covers_all(env):
    d = env.issue(days=10)
    assert L.verify_signature(d, d["sig"], env.pub)
    for field in ("limits", "features", "machine", "org", "app"):
        bad = dict(d)
        bad[field] = {"max_sessions": 999} if field == "limits" else "x"
        assert not L.verify_signature(bad, d["sig"], env.pub), "改 %s 竟然还能验签通过" % field


def t_trial(env):
    lic = env.lic(trial_days=10)
    st = lic.state()
    assert st.mode == "trial" and st.days_left == 10, (st.mode, st.days_left)
    assert not lic.allow("max_sessions", 2)[0], "试用上限没生效"
    assert lic.allow("max_sessions", 1)[0]
    env.clock.advance(11)
    st = lic.state(refresh=True)
    assert st.mode == "expired" and st.limits["max_sessions"] == 1, (st.mode, st.limits)


def t_clock_rollback(env):
    env.write(env.issue(days=365, machine=L.machine_fingerprint()))
    env.clock.advance(10)
    assert env.lic().state().ok
    env.clock.t -= 3 * 86400
    st = env.lic().state(refresh=True)
    assert st.mode == "clock_tampered" and not st.ok, (st.mode, st.reason)


def t_grace_flow(env):
    srv, url, hits = _serve()
    try:
        env.write(env.issue(days=365, machine=L.machine_fingerprint(),
                            heartbeat={"url": url, "interval_days": 7, "grace_days": 15}))
        assert env.lic().state().mode == "licensed"

        env.clock.advance(8)
        st = env.lic().state(refresh=True)
        assert st.mode == "grace" and st.ok and st.offline_days_left == 7, (st.mode, st.reason)

        assert env.lic().heartbeat()["ok"] and hits and hits[-1]["app"] == "demo"
        assert env.lic().state(refresh=True).mode == "licensed"

        env.clock.advance(16)
        st = env.lic().state(refresh=True)
        assert st.mode == "grace_expired" and st.limits["max_sessions"] == 1, (st.mode, st.reason)
    finally:
        srv.shutdown()


def t_heartbeat_down(env):
    env.write(env.issue(days=365, machine=L.machine_fingerprint(),
                        heartbeat={"url": "http://127.0.0.1:9/hb", "grace_days": 15}))
    lic = env.lic()
    assert not lic.heartbeat(timeout=1)["ok"]
    assert lic.state().ok, "心跳失败不该当场降级（由宽限期决定）"


def t_heartbeat_reject(env):
    """服务端说不行（吊销/到期）→ 本次不刷新 last_ok，但也不当场清空授权。"""
    srv, url, _ = _serve('{"ok": false, "error": "授权已吊销"}', status=403)
    try:
        env.write(env.issue(days=365, machine=L.machine_fingerprint(),
                            heartbeat={"url": url, "grace_days": 15}))
        lic = env.lic()
        r = lic.heartbeat()
        assert not r["ok"] and "吊销" in r["error"], r
        assert not lic._state.get("last_ok"), "被拒绝不该记 last_ok"
    finally:
        srv.shutdown()


def t_check_license(env):
    d = env.issue(days=30, machine=L.machine_fingerprint(), features=["pro"])
    assert L.check_license(d, env.pub, app="demo")[0]
    assert not L.check_license(d, env.pub, app="other")[0]
    assert not L.check_license(d, env.pub, app="demo", revoked=[d["id"]])[0]
    assert not L.check_license(None, env.pub, app="demo")[0]
    assert not L.check_license(d, env.pub, app="demo", now=env.clock.t + 400 * 86400)[0]
    other = {"sys": "a" * 16, "mac": "b" * 16, "disk": "c" * 16}
    ok, why = L.check_license(d, env.pub, app="demo", machine=other)
    assert not ok and "指纹" in why, why


def t_install(env):
    lic = env.lic()
    assert lic.state().mode == "trial"
    st = lic.install(json.dumps(env.issue(days=100, org="某某科技有限公司",
                                          machine=L.machine_fingerprint())))
    assert st.mode == "licensed" and st.org == "某某科技有限公司", (st.mode, st.org)
    assert os.path.isfile(env.path)


def t_label_texts():
    """每个模式都要有一句能直接给用户看的话（不能是空串/异常）。"""
    for mode in ("trial", "licensed", "grace", "expired", "grace_expired",
                 "machine_mismatch", "invalid", "clock_tampered"):
        text = L.State(mode=mode).label()
        assert text and isinstance(text, str), mode
        assert "None" not in text, (mode, text)


def main() -> int:
    print("== Ed25519 ==")
    check("RFC 8032 三组向量", t_rfc_vectors)
    check("与 cryptography 互验", t_cross_cryptography)
    check("签名口径（键排序/剔除 sig）", t_canonical_stable)

    print("== 指纹 ==")
    check("机器码 roundtrip + 校验位", with_env(t_machine_code))

    print("== 授权 ==")
    check("签发→安装→验签 全链路", with_env(t_roundtrip))
    check("别的机器上用不了", with_env(t_other_machine))
    check("指纹缺项时剩项必须全中", with_env(t_partial_fingerprint))
    check("不绑机器的授权任何机器可用", with_env(t_unbound))
    check("别的产品的授权不认", with_env(t_wrong_app))
    check("到期即失效（限 1 会话）", with_env(t_expired))
    check("到期按 UTC 算", with_env(t_expire_utc))
    check("改过的 license 验签失败", with_env(t_tampered))
    check("签名覆盖全部字段", with_env(t_sig_covers_all))
    check("试用期与试用上限", with_env(t_trial))
    check("系统时间回拨", with_env(t_clock_rollback))
    check("心跳宽限全流程", with_env(t_grace_flow))
    check("心跳打不通不降级", with_env(t_heartbeat_down))
    check("心跳被拒不当场清授权", with_env(t_heartbeat_reject))
    check("服务端 check_license 五道关", with_env(t_check_license))
    check("粘贴激活 install()", with_env(t_install))
    check("状态文案齐全", t_label_texts)

    print("\n%d 通过 / %d 失败" % (len(PASS), len(FAIL)))
    for n, e in FAIL:
        print("  ❌ %s: %s" % (n, e))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())