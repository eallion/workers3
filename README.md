# workers3

通用 S3 兼容代理，为 Mastodon 提供对象存储加速和安全访问。

## 架构

```
Mastodon SDK（已签名请求）        用户浏览器（公开访问）
  │  PUT/DELETE/POST               │  GET/HEAD
  └──────┐                         └──┐
         └──── Worker ────────────────┘
               │ AWS SigV4 转发 + 缓存头
               ▼
             COS / S3（私有）
```

- 一个域名处理所有请求，配置极简
- **写操作**：Worker 验证 Mastodon 的 AWS SigV4 签名，通过后重新签名转发到 COS
- **读操作**：公开访问，响应带强缓存头（`Cache-Control: public, max-age=31536000, immutable`），由 Cloudflare 边缘缓存加速
- Bucket 保持私有，不暴露公网

## 前提

- Cloudflare 账号（域名已在 Cloudflare 管理）
- 腾讯云 COS 或任意 S3 兼容存储
- Mastodon 实例管理员权限

## 文件结构

```
workers3/
├── _worker.js     # Worker 入口
├── wrangler.toml  # 元信息（不含 [vars]）
└── package.json   # 依赖定义
```

## 部署

### 1. COS 配置

创建存储桶（如已有则跳过），地域 `na-siliconvalley`（硅谷），权限**私有读写**。

COS → 密钥管理：获取 **SecretId** 和 **SecretKey**。

### 2. 推送到 GitHub

```bash
git remote add origin git@github.com:你的用户名/workers3.git
git push -u origin main
```

### 3. Cloudflare 连接仓库

Workers & Pages → **创建 Worker** → 名称 `workers3` → **部署** →
**设置** → **Builds** → **连接 Git 仓库** → 选中 `workers3`，分支 `main`，构建/部署命令留空 → **保存并部署**。

### 4. 绑定自定义域名

Worker → **触发器** → **自定义域名** → **添加**：

```
files.你的域名.com
```

### 5. 设置环境变量

Worker → **设置** → **变量** → **添加变量**（全部选 **Secret**）：

| 变量名 | 值 |
|---|---|---|
| `S3_ENDPOINT` | `https://你的bucket.cos.na-siliconvalley.myqcloud.com` |
| `S3_BUCKET` | 你的 bucket 名称（如 `mastodon-1251347414`） |
| `S3_REGION` | `na-siliconvalley` |
| `S3_ACCESS_KEY` | COS SecretId |
| `S3_SECRET_KEY` | COS SecretKey |
| `S3_MASTODON_IP` | （可选）Mastodon 服务器公网 IP，作为签名验证的备选 |

## Mastodon 配置

```bash
S3_ENABLED=true
S3_BUCKET=你的bucket名称
S3_ENDPOINT=https://files.你的域名.com
S3_ALIAS_HOST=files.你的域名.com
S3_REGION=na-siliconvalley
S3_PROTOCOL=https
# 桶全私有，Worker 代理，不写 ACL；设为空则跳过 ACL 设置
S3_PERMISSION=
# 有 S3_ENDPOINT 和 S3_ALIAS_HOST，此变量不被使用，注释掉或删掉
# S3_HOSTNAME=
AWS_ACCESS_KEY_ID=你的COS SecretId
AWS_SECRET_ACCESS_KEY=你的COS SecretKey
```

## 验证

```bash
# 健康检查
curl https://files.你的域名.com/health

# 写操作无签名（模拟攻击者）
curl -X DELETE https://files.你的域名.com/test/hello.txt
# 403 Forbidden

# 读操作（公开）
curl -I https://files.你的域名.com/test/hello.txt
# cf-cache-status: MISS / HIT
# Cache-Control: public, max-age=31536000, immutable
```

## 兼容存储

| 服务商 | `S3_ENDPOINT` | `S3_REGION` |
|---|---|---|
| Tencent COS（硅谷） | `https://bucket.cos.na-siliconvalley.myqcloud.com` | `na-siliconvalley` |
| AWS S3 | `https://bucket.s3.region.amazonaws.com` | 对应 region |
| Cloudflare R2 | `https://bucket.account.r2.cloudflarestorage.com` | `auto` |
| MinIO | `http://host:9000/bucket` | `us-east-1` |

## 注意事项

- Worker 免费计划 100,000 请求/天，个人实例写操作极少，完全够用
- 文件大小限制 100MB，Mastodon 默认 8-40MB，安全
- Cloudflare → COS 走 Bandwidth Alliance，出站流量 $0
- COS 不要开启腾讯 CDN 加速
