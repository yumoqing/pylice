# pylice — 单文件离线软件授权

给私有化交付的软件加授权：**Ed25519 签名 + 机器指纹 + 功能位 + 到期 + 心跳宽限**。
零第三方依赖（自带纯 Python Ed25519，只用标准库），一个文件就能放进任何离线程序。

```
pylice.py            全部实现（客户端 + 签发 + 心跳服务 + CLI），可直接拷进你的工程
tests/test_pylice.py 21 项用例（RFC 8032 向量 + 与 cryptography 互验 + 授权全链路）
```

## 装

```bash
pip install git+https://github.com/yumoqing/pylice      # 或把 pylice.py 拷进工程
```

## 5 分钟接入（任何离线程序都能用）

```bash
# ① 签发方，只做一次：生成密钥对
lice keygen
#   私钥写 ~/.pylice/issuer_ed25519.key（600，务必备份，丢了只能换公钥重发全部授权）
#   公钥贴进产品代码的 PUBKEY_HEX

# ② 客户机：报机器码（界面里显示一行字，客户截图发你）
lice machine
#   S1-849b73bc041cf8a6-656f71b116a251de-484df7e271bde091-1d

# ③ 签发方：出授权
lice issue --app myapp --org 某某公司 --days 365 \
      --features pro,export --max-sessions 5 \
      --machine S1-849b...-1d \
      --heartbeat https://license.example.com/hb \
      --out 某某公司.lic

# ④ 客户机：装（界面「粘贴授权」或命令行）
lice install 某某公司.lic --app myapp --pubkey <公钥hex>
```

产品代码里只有这几行：

```python
from pylice import License

lic = License(app="myapp", pubkey=PUBKEY_HEX)     # 授权文件默认落在用户配置目录
st = lic.state()                                  # 启动时算一次
status_label.setText(st.label())                  # "已授权：某某公司 · 2027-11-19 到期"

if not lic.has("export"):                         # 功能位
    disable_export_button()

ok, why = lic.allow("max_sessions", open_tabs)    # 数量门禁；False 时 why 可直接显示
if lic.data and (lic.data.get("heartbeat") or {}).get("url"):
    lic.heartbeat_async()                         # 后台线程，绝不阻塞启动
```

要签发/心跳服务又不想写代码：`lice issue` / `lice serve --dir licenses --port 8787 --app myapp --pubkey <hex>`
（服务端会校验签名、归属、到期、机器指纹，支持 `--revoke` 吊销授权号）。

## 状态与降级

| mode | 含义 | ok |
|---|---|---|
| `trial` | 没授权文件，试用中（默认 30 天 / 2 个会话） | ✅ |
| `licensed` | 正常授权 | ✅ |
| `grace` | 心跳太久没成功，但还在宽限期内（界面该提示联网） | ✅ |
| `expired` | 授权/试用已到期 → 限额降到 1 个会话 | ❌ |
| `grace_expired` | 宽限用完 → 限额降到 1 个会话 | ❌ |
| `machine_mismatch` | 换了机器（指纹对不上） | ❌ |
| `invalid` | 验签失败 / 不属于本产品 / 到期日坏了 | ❌ |
| `clock_tampered` | 系统时间被回拨 | ❌ |

`❌` 不等于"打不开"：`limits` 会退到最小可用（默认 `max_sessions=1`）。把客户数据锁死会直接毁掉续费谈判。

## 不变量（换语言重写也要满足）

- **签名覆盖除 `sig` 外全部字段**，规范化 JSON（键排序 + 紧凑分隔符 + UTF-8）。手改一个字符就验签失败，
  所以 license 文件不需要加密、不需要藏。
- **机器指纹三项**：系统 UUID / 主网卡 MAC / 系统盘序列号，只存 sha256 前 16 位。
  license 里出现的项**必须全中**，留空的项不参与比对；`machine` 整体为空 = 不绑机器（任何机器可用）。
- **到期按 UTC 当天 23:59:59**（`calendar.timegm`，不是 `time.mktime`：后者按本机时区解释，
  UTC+8 下会让客户提前一天被锁）。
- **心跳不降级**：打不通只记 `hb_fail`，能否用由 `last_ok`/`installed_at` + `grace_days` 决定；
  宽限从安装时刻起算，纯内网客户装完必须能正常跑。
- **时钟回拨只做粗检测**（记录历史最大值，回退超 6 小时判异常）：抬高"改时间续命"的成本，不是安全边界。
- **时间一律注入 `now()`**：测试用可推进的 Clock，绝不 sleep 真实天数。
- **门禁放在能提示用户的那一层**：底层静默拒绝 = 丢功能；上层拒绝要带"为什么 + 怎么升"。

## 跨平台指纹来源

| 平台 | sys | disk |
|---|---|---|
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` 的 `0` 项（不用 wmic——Win11 24H2 已删） |
| Linux | `/etc/machine-id` | `/sys/block/{sd,nvme,vd}*/…/serial` |
| macOS | `ioreg IOPlatformExpertDevice` 的 `IOPlatformUUID` | 同一份 `IOPlatformSerialNumber` |

取不到的位记空串，**不参与比对**，也不会因此锁死客户。

## 边界（别当成防破解）

这是**涨价门槛**，不是复制保护：它让授权可签发、可到期、可吊销、可按功能位卖。
真要守住核心，得让核心不在客户机上（SaaS / 混合部署），或者上 PyArmor / Nuitka 抬高读代码的成本——
那与 license 无关。对外别承诺"无法破解"，承诺"正版可升级、可追责、可开票"。

## 谁在用

- [sshdesk](https://github.com/yumoqing/sshdesk)：`sshdesk/license.py` 只有产品参数（app 名、公钥、试用口径）。

## 开发

```bash
python tests/test_pylice.py     # 21 项，零依赖；装了 cryptography 会多做两组互验
```