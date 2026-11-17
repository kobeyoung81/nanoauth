# nanoauth

你是谁：账号、令牌，以及所有服务用来验签的那套公钥。

它是八个一级服务之一。它拥有 `auth_` 前缀，把签名过的身份交给整个平台。

## 它是什么

- **账号与凭据。** 注册、bcrypt 哈希、状态与档位；全新安装的第一个账号就是管理员。
- **RS256 令牌与 JWKS。** 给所有服务用的访问令牌、可轮换的刷新票据，以及一个稳定地址上的公钥集。
- **渠道身份。** 一个人可以在多个聊天平台上被找到；绑定存在账号文档里。
- **目录登录。** LDAP 与 Active Directory，配置在管理模块里，与本地密码走同一条凭据路径。
- **登录界面。** 登录页在这里构建，由门户以 `auth` 插件的形式提供。

## 它在哪

| | |
|---|---|
| 集合 | `auth_users`、`auth_secrets`、`auth_refresh_tokens`、`auth_oauth_providers`、`auth_git_shortcuts` |
| 端口 | 网络内 `8081`，宿主机 `14401`（绑 loopback） |
| 上游 | 浏览器、网关、小程序，以及每一个要验令牌的服务 |
| 下游 | `nanoadmin` —— 配置（密钥对、目录设置）与审计 |
| 端点 | `/auth/v1/*`，以及 `/plugins/auth/` 下的前端产物 |

## 快速开始

```bash
go build ./cmd/nanoauth
NANOAUTH_MONGO_URI="mongodb://localhost:27017/nanosec" \
NANOSEC_ADMIN_URL="http://localhost:14404" \
NANOSEC_BUS_INTERNAL_TOKEN="…" \
  ./nanoauth
```

不需要挂任何密钥文件：RSA 密钥对首次启动时生成，写进管理模块的配置
（`admin_config`，组件 `auth`），所以每个副本用同一把密钥签名。

## 配置

| 变量 | 含义 |
|---|---|
| `NANOAUTH_MONGO_URI` | 平台库；未设时回退到 `NANOSEC_BUS_DATABASE_URI` |
| `NANOAUTH_ADDR` | 监听地址，默认 `:8081` |
| `NANOSEC_ADMIN_URL` | 配置与审计在哪儿 |
| `NANOSEC_BUS_INTERNAL_TOKEN` | 管理模块内部面的共享密钥 |
| `NANOAUTH_JWT_KEY_ID` | 随公钥集发布的 `kid` |
| `NANOAUTH_TOKEN_TTL` / `NANOAUTH_REFRESH_TTL` | 访问令牌与刷新票据的有效期，单位秒 |
| `NANOAUTH_WECHAT_APP_ID` / `NANOAUTH_WECHAT_APP_SECRET` | 小程序登录 |
| `NANOAUTH_UI_DIR` | 要挂在 `/plugins/auth/` 的前端产物；留空则关闭 |

目录设置 —— 主机、绑定 DN、base DN、过滤器 —— 属于配置而不是环境变量：
放在 `ldap.*` 下，在控制台编辑。

## API

| 端点 | 做什么 |
|---|---|
| `POST /auth/v1/register` | 创建账号 |
| `POST /auth/v1/token` | 密码登录或目录登录 → 访问令牌 + 刷新票据 |
| `POST /auth/v1/token/refresh` | 轮换票据，换一枚新的访问令牌 |
| `POST /auth/v1/logout` | 作废票据 |
| `GET /auth/v1/userinfo` | 用 bearer 令牌换 claims |
| `POST /auth/v1/oauth/wechat` | 小程序登录 |
| `GET /auth/v1/.well-known/jwks` | 公钥集 |
| `GET /healthz`、`GET /metrics` | 存活与 Prometheus |

## 设计决策

- **一次写就建出一个人。** 账号与它的渠道身份是同一次 `insertOne`，不会出现半开户的用户带着一条孤儿渠道记录。
- **刷新令牌是票据，不是 JWT。** 它是一个存在 `auth_refresh_tokens` 里的随机串，所以登出与轮换是真的撤销。
- **密钥对在配置里。** 生成一次、每个副本都读，轮换只需换那个值 —— 没有密钥卷要挂。
- **目录只认证，不存储。** 绑定成功返回一个身份，这个服务把它映射到账号；目录本身从不写入。

## 文档

- [`docs/ACCOUNT_MANAGEMENT_DESIGN.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/ACCOUNT_MANAGEMENT_DESIGN.md) —— 账号、渠道与会话
- [`docs/ARCHITECTURE.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/ARCHITECTURE.md) —— 它所在的整个平台
- [`docs/README.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/README.md) —— 全部文档索引

## 状态

随 `v0.1.0` 发布；本模块的版本钉在超仓的 `versions.lock` 里。

## 贡献与安全

开发与提交规则见
[`CONTRIBUTING.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/CONTRIBUTING.md)；
漏洞请按
[`SECURITY.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/SECURITY.md) 私下报告，
不要开公开 issue。

## 许可证

[AGPL-3.0](./LICENSE)。名称与标志另有说明 —— 见 [`NOTICE`](./NOTICE)。
