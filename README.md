# YunTransfer Telegram Bot

一个基于 Docker Compose 一键部署的 Telegram 多网盘转存机器人，支持 **百度网盘**、**PikPak**、**夸克网盘** 分享链接一键转存，并可选联动 **OpenList** 实现免密目录分享与 **最高 2000 MiB 视频/图片直接发回 Telegram 在线预览**。

---

## 功能亮点

- **三大网盘防噪与批量转存**：内置支持百度网盘（`/baidu`）、PikPak（`/pikpak`）、夸克网盘（`/quark`）。直接转发带广告、书名号或截断标题的官方分享文案，自动提取链接与提取码；**支持一条消息同时粘贴多条分享链接（单次最多 20 条，私聊支持多网盘混发批量转存）**，单链接私聊也支持先发链接、后补提取码。
- **独立子目录 & `-n` 直存双模式**：
  - **默认模式**：自动在保存目录下新建 `<日期>_<任务ID>` 独立文件夹，不同任务互不干扰。
  - **`-n` 直存模式**：命令或消息中附带 `-n`，直接存入网盘目标目录，并精确记录本次转存的文件归属。
- **OpenList 免密分享页（可选）**：转存完成后一键生成有效期可控（默认 24 小时）的 `/@s/` 免密分享链接，无需暴露底层直链。
- **突破 50MB 限制，最高 2GB 媒体直发（可选）**：自带本地 `telegram-bot-api` 容器，转存目录内的视频、动图、图片（单文件最高约 `1995 MiB`）可一键流式发送到 Telegram 直接播放预览，发送完毕自动清理宿主机临时文件。
- **内置可视化 Web 管理后台**：管理员私聊发送 `/web` 获取 5 分钟有效的一次性免密登录链接，在网页端即可完成网盘授权、参数调整、用户黑白名单/群组白名单管理及全局任务清理。
- **安全连带删除**：支持在 Telegram 内经二次确认后一键撤销 OpenList 分享并同步删除对应的网盘文件；若切换过网盘账号或移动改名过文件，会自动拦截或跳过，防止误删已有数据。

---

## 1. 快速部署（5 分钟上手）

### 1.1 准备 Telegram 基础凭证

部署前需准备以下 4 项信息：

1. **`TELEGRAM_API_ID` 与 `TELEGRAM_API_HASH`**：
   - 登录 [https://my.telegram.org](https://my.telegram.org) $\rightarrow$ 进入 **API development tools** 创建应用获取（用于驱动本地大文件 Bot API 容器）。
2. **`TELEGRAM_BOT_TOKEN`**：
   - 在 Telegram 私聊 `@BotFather` 发送 `/newbot` 创建机器人获取。
3. **`TELEGRAM_ADMIN_ID`**：
   - 管理员本人的 Telegram 纯数字用户 ID（正整数，可通过 `@userinfobot` 等工具查询）。

> [!IMPORTANT]
> **旧机器人切换必看**：如果你的 `TELEGRAM_BOT_TOKEN` 之前连接过官方 `api.telegram.org`（跑过其他程序），启动本项目前**必须先从官方服务器登出一次**，否则本地容器无法拉取消息（全新创建的 Token 无需此步）：
> ```bash
> read -rsp "粘贴 TELEGRAM_BOT_TOKEN: " BOT_TOKEN && echo
> curl -sS -X POST "https://api.telegram.org/bot${BOT_TOKEN}/deleteWebhook" && echo
> curl -sS -X POST "https://api.telegram.org/bot${BOT_TOKEN}/logOut" && echo
> unset BOT_TOKEN
> ```
> 返回 `{"ok":true,"result":true}` 即登出成功，之后切勿再请求官方 API，直接启动下方容器即可。

### 1.2 初始化目录与配置文件

在项目根目录执行以下命令，创建持久化目录并对齐容器运行权限（容器内固定以 `UID:GID = 101:101` 非特权用户运行，非 `root` 用户请在 `chown` 前加 `sudo`）：

```bash
mkdir -p ./data/pikpak ./data/tmp_uploads ./tg_api_data
chmod 700 ./data ./data/pikpak
chown -R 101:101 ./data ./tg_api_data
cp .env.example .env
```

**挂载目录说明**：
- `./data`：存放核心 SQLite 数据库（`bot.db`）、网盘授权凭证与动态配置，重启不丢失。
- `./data/tmp_uploads`：`bot` 与 `telegram-bot-api` 双容器共享的临时大文件中转目录，实现本地零拷贝秒传，单文件发完立即自动删除。
- `./tg_api_data`：本地 `telegram-bot-api` 容器自身的会话与状态缓存目录。

### 1.3 编辑 `.env` 并启动服务

编辑 `.env`，至少填好前两节必填项（`TELEGRAM_API_ID`、`TELEGRAM_API_HASH`、`TELEGRAM_BOT_TOKEN`、`TELEGRAM_ADMIN_ID` 及 `WEB_BASE_URL`），其余网盘和 OpenList 配置既可以先写在 `.env` 中，也可以启动后在 `/web` 网页后台填写：

```bash
docker compose up -d --build
```

查看运行状态与日志：

```bash
docker compose ps
docker compose logs -f bot
```

看到 `Connected to local Telegram Bot API` 与 `Start polling` 即代表部署成功。

---

## 2. 网盘与 OpenList 授权配置指南

### 2.1 进入 Web 管理后台

使用管理员账号在 Telegram **私聊**机器人发送：

```text
/web
```

机器人会返回一条 5 分钟内有效、仅限单次点击的登录链接（形如 `https://你的域名/login#token=...`），点击即可直接进入管理后台。

---

### 2.2 百度网盘配置（OAuth 2.0 授权码）

1. 前往 [百度网盘开放平台控制台](https://pan.baidu.com/union/console/applist) 创建或查看你的应用。
2. 在 `.env` 或 Web 后台填写应用密钥：
   - `BAIDU_CLIENT_ID`：填写 **32 位字母数字的 `AppKey`**（**注意：切勿填成 9 位纯数字的 `AppID`**，否则授权页会报错 `invalid_client / 应用不存在`）。
   - `BAIDU_CLIENT_SECRET`：填写对应的 32 位 **`SecretKey`**。
3. 打开机器人 `/web` 后台 $\rightarrow$ **网盘配置与授权** $\rightarrow$ **百度网盘**：
   - 点击 **「打开百度授权页面」**，登录你的百度网盘账号并同意授权；
   - 复制网页上显示的授权码，粘贴回后台输入框并提交，即完成绑定（后续 Token 过期会自动刷新续期）。

---

### 2.3 PikPak 配置（设备码登录 或 PAT 令牌）

任选以下一种方式即可：

- **方式一：网页设备码授权（推荐，免抓包）**
  - 进入 `/web` 后台 $\rightarrow$ **网盘配置与授权** $\rightarrow$ **PikPak**，点击发起设备码授权；
  - 按页面提示打开验证网址并输入显示的设备码，后台会自动轮询并完成绑定。
- **方式二：Personal Access Token（`PIKPAK_PAT`）**
  - 在 `.env` 的 `PIKPAK_PAT=` 或 `/web` 后台粘贴你的 PikPak PAT 令牌保存即可，启动时会自动验权绑定。

> [!NOTE]
> **关于 `/pikpak -n` 直存开关（`PIKPAK_DIRECT_EXCLUSIVE_DIR`）**：
> 由于官方 PikPak CLI 转存时不直接返回新建文件 ID，`/pikpak -n` 直存通过对比目录前后快照来识别新文件。如果同一时刻有其他程序或人工也在往 `PIKPAK_SAVE_PATH` 里传文件，可能会把外部文件也算进当前任务。因此默认仅开放安全的子目录模式（`/pikpak <链接>`）；只有当你确认 `PIKPAK_SAVE_PATH` 目录专门给本机器人独占写入时，再开启 `PIKPAK_DIRECT_EXCLUSIVE_DIR=true`。

---

### 2.4 夸克网盘配置（网页版 Cookie）

1. 打开浏览器的 **无痕 / 隐私窗口**，访问 [https://pan.quark.cn](https://pan.quark.cn) 并登录夸克账号。
2. 按 `F12` 打开开发者工具 $\rightarrow$ 切换到 **网络（Network）** 面板，刷新页面，点开任意一条发往 `drive-pc.quark.cn` 或 `pan.quark.cn` 的请求，复制 **请求标头（Request Headers）** 中完整的 `Cookie` 值。
3. 填入 `.env` 的 `QUARK_COOKIE=` 或粘贴到 `/web` 后台保存（机器人会自动拦截响应头滚动续期 `__puus` 并定期保活）。

> [!TIP]
> **防顶号提示**：如果你的 OpenList 也使用网页 Cookie 驱动挂载同一个夸克账号，**请务必用两个不同的无痕窗口分别登录提取两份独立的 Cookie**（或者 OpenList 侧改用 Quark TV 驱动），不要把同一份 Cookie 直接复制给两边共用，否则双端刷新会互相顶掉登录态。

---

### 2.5 OpenList 对接与路径映射（可选）

如果不需要生成分享链接和 Telegram 媒体直发，保持 `OPENLIST_BASE_URL=` 为空即可，机器人会自动跳过 OpenList 流程。如需启用：

1. **获取 `OPENLIST_TOKEN`**：
   - 登录 OpenList 管理后台 $\rightarrow$ **设置** $\rightarrow$ **其他** $\rightarrow$ 找到 **令牌（Token）** 复制填入 `OPENLIST_TOKEN`（直接填原始字符串，**不要加 `Bearer ` 前缀**）。
   - 推荐使用 OpenList 管理员令牌（或 `base_path` 为 `/` 且勾选了「创建分享」权限的账号；若使用非管理员普通账号，需在 OpenList 对应百度/夸克存储设置中打开 **网页代理 `WebProxy`** 开关才能直发媒体）。
2. **`OPENLIST_BASE_URL` 与 `OPENLIST_PUBLIC_URL` 的区别**：
   - `OPENLIST_BASE_URL`：机器人容器访问 OpenList API 的地址（例如公网 `https://openlist.example.com`，或同机内网地址）。
   - `OPENLIST_PUBLIC_URL`：生成 `/@s/xxxx` 分享链接发给用户点击的外部公网域名。**如果 `OPENLIST_BASE_URL` 本身就是公网域名，留空 `OPENLIST_PUBLIC_URL` 即可自动复用。**
3. **网盘保存路径与 OpenList 路径必须一一对应（最常见易错点）**：
   请根据你在 OpenList 后台挂载存储时设置的「根文件夹路径/ID」对齐填写：

   | 你在 OpenList 里的挂载方式 | 网盘保存路径（`*_SAVE_PATH`）示例 | OpenList 对应路径（`OPENLIST_*_PATH`）填法 |
   | :--- | :--- | :--- |
   | `/quark` 挂载的是夸克**整个网盘根目录 `/`** | `QUARK_SAVE_PATH=/来自：分享` | `OPENLIST_QUARK_PATH=/quark/来自：分享` |
   | `/quark` **直接挂载了 `/来自：分享` 子文件夹** | `QUARK_SAVE_PATH=/来自：分享` | `OPENLIST_QUARK_PATH=/quark` |
   | `/bdshare` **直接挂载了 `/转存文件` 子文件夹** | `BAIDU_SAVE_PATH=/转存文件` | `OPENLIST_BAIDU_PATH=/bdshare` |
   | `/pikpak` **直接挂载了 `/Pack From Shared`** | `PIKPAK_SAVE_PATH=/Pack From Shared` | `OPENLIST_PIKPAK_PATH=/pikpak` |

---

## 3. 日常使用指南

### 3.1 Telegram 命令一览

| 命令 / 发送方式 | 适用范围 | 用途说明 |
| :--- | :--- | :--- |
| `/start` / `/help` | 私聊 / 授权群聊 | 查看机器人支持的功能与命令说明 |
| `[-n] <1~20条分享文案或链接>` | **仅私聊** | 自动识别单条或多条（百度 / PikPak / 夸克可混发）链接并逐个建任务转存；单链接没带提取码可在下一条补发 |
| `/baidu [-n] <1~20条链接> [提取码]` | 私聊 / 授权群聊 | 指定转存单条或多条百度网盘分享（加 `-n` 为不建子目录直存；多条链接请在每条后附对应提取码或 `?pwd=`） |
| `/pikpak [-n] <1~20条链接> [提取码]` | 私聊 / 授权群聊 | 指定转存单条或多条 PikPak 分享 |
| `/quark [-n] <1~20条链接> [提取码]` | 私聊 / 授权群聊 | 指定转存单条或多条夸克网盘官方分享链接（`pan.quark.cn/s/` 或 `quark.cn/s/`） |
| `/tasks` | 私聊 / 授权群聊 | 分页查看自己的历史转存记录（管理员可查看全部记录）并支持一键连带删除 |
| `/web` | **仅管理员私聊** | 获取 5 分钟有效的一次性 Web 管理后台登录链接 |

**群聊防打扰设计**：在已授权的群组中，机器人只响应明确的命令（如 `/quark https://...`）、针对缺提取码提示的回复消息，以及任务面板上的按钮点击，不会对群友日常闲聊产生误触发。

### 3.2 任务面板按钮说明

转存完成后，消息面板会根据任务模式和文件类型提供对应操作按钮：

- **`[🔗 返回OpenList分享链接]`**（仅默认子目录模式显示）：按需生成免密目录分享页；有效期内重复点击直接复用，临近过期时自动撤销旧链接换新。
- **`[📤 通过Telegram直接发送]`**（当目录内完整探测到 `1 ~ MAX_DELIVERY_FILES` 个视频/图片时显示）：将媒体文件流式发送到当前聊天窗口，支持在线播放预览；无法预览的编码会自动免重下转为普通文件发送。
- **`[🗑️ 删除本次转存]`**：点击后弹出二次确认，确认后自动先撤销 OpenList 分享链接，再清理对应的网盘目录/文件并移除记录。

### 3.3 访问权限与群组白名单说明

机器人的访问控制优先级固定为：**管理员（永远放行） $\rightarrow$ 用户黑名单（一票否决） $\rightarrow$ 白名单机制（默认开启）**。

- **如何授权指定群组及群成员使用**：
  Telegram 群组与超级群组的 ID 均为**带负号的数字**（如 `-1001234567890`）。多个 ID 之间用**英文逗号 `,`** 分隔，不要加引号：
  ```dotenv
  INITIAL_GROUP_WHITELIST_IDS=-1001234567890,-1009876543210
  ```
  把群组加入「群组白名单」（且机器人已在群内）后：不仅可以在该群内使用命令，**该群的所有在群成员在私聊机器人时也会自动获得白名单权限**，无需逐个添加个人 ID；成员退群后缓存到期自动收回权限。
- 首次启动后，你随时可以在 `/web` 后台 **「访问控制名单」** 页面动态增删个人白名单、群组白名单与黑名单，或关闭白名单限制（改为公开可用 + 黑名单拉黑模式）。

---

## 4. 公网 HTTPS 反向代理配置（推荐）

如果在公网服务器部署并通过域名访问 `/web` 管理后台，建议将 `WEB_BIND_HOST` 设为 `127.0.0.1`，交由 Caddy 或 Nginx 提供根路径 HTTPS 反代：

### 4.1 `.env` 反代配套设置

```dotenv
WEB_BIND_HOST=127.0.0.1
WEB_HOST_PORT=38082
# 注意：WEB_BASE_URL 必须是根域名（scheme://host[:port]），不能带 /bot 等子路径
WEB_BASE_URL=https://bot.example.com
# 填入本机与 Docker 网桥网段，使登录防爆破限流能识别真实访客 IP
WEB_TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12
```

### 4.2 Caddy v2 配置示例（`Caddyfile`，自动申请与续期证书）

```caddyfile
bot.example.com {
    request_body {
        max_size 128KB
    }

    reverse_proxy 127.0.0.1:38082
}
```

### 4.3 Nginx 配置示例

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name bot.example.com;

    ssl_certificate     /etc/nginx/ssl/bot.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/bot.example.com.key;

    client_max_body_size 128k;

    location / {
        proxy_pass http://127.0.0.1:38082;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 5. 环境变量参考表

配置优先级为 **`Web 后台保存值（SQLite） > .env 环境变量 > 默认值`**。其中标有 **「仅 `.env` 只读」** 的三项安全信任根无法在网页修改（改动后需执行 `docker compose up -d bot` 生效）。

| 变量名 | 必填 | 默认值 | Web 可改 | 说明 |
| :--- | :---: | :--- | :---: | :--- |
| `TELEGRAM_API_ID` | 是 | — | 否 | `my.telegram.org` 申请的数字 `api_id` |
| `TELEGRAM_API_HASH` | 是 | — | 否 | `my.telegram.org` 申请的 32 位 `api_hash` |
| `TELEGRAM_BOT_TOKEN` | 是 | — | 否 | `@BotFather` 签发的机器人 Token |
| `TELEGRAM_ADMIN_ID` | 是 | — | **仅 `.env` 只读** | 唯一管理员的 Telegram 数字用户 ID |
| `WEB_BASE_URL` | 否 | `http://127.0.0.1:38082` | **仅 `.env` 只读** | Web 后台对外根访问地址（严禁带子路径） |
| `WEB_TRUSTED_PROXIES` | 否 | 空 | **仅 `.env` 只读** | 可信反代 IP/CIDR 列表（英文逗号分隔） |
| `WEB_BIND_HOST` | 否 | `0.0.0.0` | 否 | 宿主机监听地址（挂反代时建议改 `127.0.0.1`） |
| `WEB_HOST_PORT` | 否 | `38082` | 否 | 宿主机映射端口（推荐 `30000`~`59999`） |
| `TZ` | 否 | `Asia/Shanghai` | 否 | 容器时区（决定默认子目录 `<yyyymmdd>` 日期） |
| `WHITELIST_ENABLED` | 否 | `true` | 是 | 是否开启白名单门禁 |
| `INITIAL_WHITELIST_IDS` | 否 | 空 | 首次导入 | 初始放行的个人用户 ID（逗号分隔） |
| `INITIAL_BLACKLIST_IDS` | 否 | 空 | 首次导入 | 初始封禁的个人用户 ID（逗号分隔） |
| `INITIAL_GROUP_WHITELIST_IDS` | 否 | 空 | 首次导入 | 初始放行的群组 ID（如 `-100xxx,-100yyy`） |
| `OPENLIST_BASE_URL` | 否 | 空 | 是 | OpenList 服务地址（留空则关闭分享与直发） |
| `OPENLIST_PUBLIC_URL` | 否 | 空 | 是 | 分享链接外部公网域名（留空则同 `OPENLIST_BASE_URL`） |
| `OPENLIST_TOKEN` | 否 | 空 | 是 | OpenList 静态令牌（推荐填管理员令牌） |
| `OPENLIST_USERNAME` / `PASSWORD` | 否 | 空 | 是 | 未填静态令牌时的备选 OpenList 账密 |
| `OPENLIST_BAIDU_PATH` | 否 | `/baidu/转存文件` | 是 | 百度保存目录在 OpenList 中的挂载路径 |
| `OPENLIST_PIKPAK_PATH` | 否 | `/pikpak/转存文件` | 是 | PikPak 保存目录在 OpenList 中的挂载路径 |
| `OPENLIST_QUARK_PATH` | 否 | `/quark/转存文件` | 是 | 夸克保存目录在 OpenList 中的挂载路径 |
| `OPENLIST_SHARE_TTL_HOURS` | 否 | `24` | 是 | OpenList 免密分享有效期（`1`~`720` 小时） |
| `BAIDU_CLIENT_ID` | 否 | 空 | 是 | 百度网盘开放平台 **32 位 `AppKey`** |
| `BAIDU_CLIENT_SECRET` | 否 | 空 | 是 | 百度网盘开放平台 **`SecretKey`** |
| `BAIDU_SAVE_PATH` | 否 | `/转存文件` | 是 | 百度网盘转存保存路径（不能为 `/`） |
| `PIKPAK_SAVE_PATH` | 否 | `/My Pack/转存文件` | 是 | PikPak 转存保存路径（不能为 `/`） |
| `PIKPAK_PAT` | 否 | 空 | 是 | PikPak Personal Access Token（或后台用设备码） |
| `PIKPAK_DIRECT_EXCLUSIVE_DIR` | 否 | `false` | 是 | 确认 PikPak 目录独占写入后允许 `/pikpak -n` |
| `QUARK_SAVE_PATH` | 否 | `/转存文件` | 是 | 夸克网盘转存保存路径（不能为 `/`） |
| `QUARK_COOKIE` | 否 | 空 | 是 | 夸克网页版初始 Cookie（或后台提交） |
| `MAX_DELIVERY_FILES` | 否 | `10` | 是 | 单任务允许直发的最大媒体文件数（`1`~`50`） |
| `MAX_TEMP_DISK_MB` | 否 | `2560` | 是 | 临时下载目录允许占用的最大空间（MiB） |
| `PENDING_INPUT_TTL_SECONDS` | 否 | `600` | 是 | 等待补发提取码的超时秒数（`60`~`3600`） |
| `MAX_RETAINED_TASKS` | 否 | `1000` | 是 | 数据库最多保留的历史任务条数（自动裁剪旧记录） |
| `LOG_LEVEL` | 否 | `INFO` | 是 | 日志级别（`DEBUG` / `INFO` / `WARNING` / `ERROR`） |

---

## 6. 升级、备份与常见问题（FAQ）

### 6.1 更新代码或修改 `.env` 后重新部署

```bash
# 仅修改了 .env 环境变量时：
docker compose up -d bot

# 拉取了新代码需重新构建镜像时：
docker compose up -d --build
```

### 6.2 安全备份数据库与凭证

> [!CAUTION]
> 数据库采用 SQLite `WAL` 模式运行，**请勿在容器运行期间直接用 `cp` 单独拷贝 `./data/bot.db`**（可能遗漏 `bot.db-wal` 中的最新数据）。备份文件包含网盘授权凭证，请妥善保管权限。

- **在线热备（推荐，无需停机）**：
  ```bash
  mkdir -p ./backup && chmod 700 ./backup
  sqlite3 ./data/bot.db ".backup './backup/bot.db'"
  chmod 600 ./backup/bot.db
  ```
- **停机完整备份（迁移服务器时使用）**：
  ```bash
  mkdir -p ./backup && chmod 700 ./backup
  docker compose stop bot
  cp -a ./data "./backup/data_$(date +%Y%m%d_%H%M%S)"
  docker compose start bot
  ```

### 6.3 常见问题排查

1. **百度网盘点击授权链接提示 `invalid_client` 或 `应用不存在`？**
   - 检查 `BAIDU_CLIENT_ID` 是否误填成了纯数字的 `AppID`。请改为百度开放平台应用详情页中 **32 位字母数字的 `AppKey`**。
2. **为什么 `.env` 里填好了 `BAIDU_CLIENT_ID` 和 `BAIDU_CLIENT_SECRET`，发百度链接还是提示尚未授权？**
   - 百度网盘采用 OAuth 2.0 授权码机制，`AppKey` + `SecretKey` 只是应用本身的身份，还需要私聊机器人发送 `/web` 进入后台，在「百度网盘」卡片点击打开授权页登录一次百度并提交授权码，才能绑定到你的个人网盘账号。
3. **转存成功了，但为什么没有出现 `[📤 通过Telegram直接发送]` 按钮？**
   - 仅当满足以下条件时才会展示直发按钮：① 已配置 OpenList 且 `OPENLIST_*_PATH` 与 `*_SAVE_PATH` 路径对齐；② 本次转存内容全部为压缩包/文档等非视频图片，或媒体文件数量超过了 `MAX_DELIVERY_FILES`（默认 `10` 个），都不会展示直发按钮（默认模式下仍可点击 `[🔗 返回OpenList分享链接]` 下载）。
4. **点击历史任务的分享或删除按钮时提示「账号或挂载绑定已变更」？**
   - 这是安全保护机制：当你手动更换了网盘账号凭证，或在后台修改了保存路径 / OpenList 挂载路径后，旧任务记录与当前新环境不再对应，系统会自动拦截云端删除操作以防误删新目录中的文件（管理员可在后台仅移除本地旧记录）。
5. **私聊点击 `/web` 链接提示登录失败或 `Origin` 校验未通过？**
   - `/web` 生成的一次性链接仅限 5 分钟内点击一次（注意部分聊天软件的链接预览功能如果提前请求了页面，一般不会消耗 `#token=` Hash，但请勿重复刷新已失效令牌，重新发一次 `/web` 即可）；同时确认你浏览器地址栏访问的域名协议与 `.env` 中的 `WEB_BASE_URL` 完全一致。
