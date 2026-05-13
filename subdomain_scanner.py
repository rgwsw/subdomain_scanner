#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
子域名资产扫描工具 (Subdomain Asset Scanner) v1.0
===========================================================
功能列表：
  1. 子域名探测（字典爆破 + 多线程）
  2. DNS 解析（A 记录，支持多 IP）
  3. IP C 段扫描（C 段 1~254 存活探测）
  4. 端口扫描（TCP Connect，多线程）
  5. URL 提取（HTTP GET + 正则提取绝对/相对 URL）
  6. 进度展示（tqdm 进度条）
  7. 结果自动保存（按时间戳创建独立目录）
  8. 泛解析检测
  9. 实时统计信息

用法示例：
  python subdomain_scanner.py -d example.com
  python subdomain_scanner.py -d example.com -f subdomains.txt -t 100
  python subdomain_scanner.py -d example.com --no-c --no-p --no-u
  python subdomain_scanner.py -d example.com -p 80 443 8080 8443
===========================================================
"""

import argparse
import socket
import threading
import queue
import re
import json
import os
import sys
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from urllib.parse import urljoin, urlparse

# ============================================================
# 第三方库导入（带友好的错误提示）
# ============================================================
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] 缺少 requests 库，请执行: pip install requests")
    sys.exit(1)

try:
    from dns import resolver as dns_resolver
    from dns import exception as dns_exception
except ImportError:
    print("[!] 缺少 dnspython 库，请执行: pip install dnspython")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    # 如果 tqdm 不可用，提供降级实现
    class tqdm:
        """降级版 tqdm，当用户未安装 tqdm 时使用"""
        def __init__(self, iterable=None, desc=None, total=None, unit="", leave=True, 
                     ncols=None, mininterval=0.1, miniters=1, ascii=None, disable=False):
            self.iterable = iterable
            self.desc = desc or ""
            self.total = total if total is not None else (len(iterable) if iterable else 0)
            self.unit = unit
            self.leave = leave
            self.n = 0
            self.start_time = time.time()
            self.disable = disable
            if self.iterable is not None and not self.disable:
                print(f"{self.desc}: 0/{self.total}", end="", flush=True)

        def __iter__(self):
            if self.disable:
                for item in self.iterable:
                    yield item
                return
            for i, item in enumerate(self.iterable):
                yield item
                self.n = i + 1
                self._update_print()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            if not self.disable:
                self._update_print(force=True)
                print()

        def update(self, n=1):
            self.n += n
            if not self.disable and (self.n % max(1, self.total // 100) == 0 or self.n >= self.total):
                self._update_print()

        def _update_print(self, force=False):
            if self.disable:
                return
            elapsed = time.time() - self.start_time
            rate = self.n / elapsed if elapsed > 0 else 0
            eta = (self.total - self.n) / rate if rate > 0 else 0
            pct = self.n / self.total * 100 if self.total > 0 else 0
            bar_len = 30
            filled_len = int(bar_len * self.n // self.total) if self.total > 0 else 0
            bar = "█" * filled_len + "░" * (bar_len - filled_len)
            msg = f"\r{self.desc}: {bar} {pct:.0f}% | {self.n}/{self.total} | {rate:.1f}{self.unit}/s | ETA: {eta:.0f}s"
            if force:
                # 用换行结束
                print(msg)
            else:
                print(msg, end="", flush=True)

        def close(self):
            if not self.disable:
                self._update_print(force=True)
                print()


# ============================================================
# 常量与全局配置
# ============================================================
SOCKET_TIMEOUT = 3
HTTP_TIMEOUT = 5
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
MAX_RESPONSE_BYTES = 500000  # URL 提取时限制响应体大小

DEFAULT_SUBDOMAINS = [
    "www", "mail", "admin", "blog", "forum", "api", "dev", "test",
    "staging", "beta", "shop", "store", "wiki", "support", "help",
    "status", "cdn", "assets", "static", "img", "video", "app",
    "portal", "remote", "vpn", "webmail", "mx", "pop3", "smtp",
    "imap", "ftp", "sftp", "ssh", "git", "jenkins", "jira",
    "confluence", "grafana", "prometheus", "monitor", "dashboard",
    "analytics", "backup", "db", "database", "mysql", "redis",
    "elasticsearch", "kibana", "logstash", "nexus", "artifactory",
    "docker", "k8s", "kubernetes", "swagger", "docs", "api-docs",
    "sdk", "download", "files", "uploads", "media", "news",
    "events", "calendar", "chat", "team", "meet", "zoom",
    "live", "stream", "tv", "radio", "newsletter", "survey",
    "feedback", "tracker", "issues", "board", "whiteboard",
    "ns1", "ns2", "ns3", "ns4", "dns1", "dns2", "mail1", "mail2",
    "smtp1", "smtp2", "pop", "imap1", "imap2", "owa", "exchange",
    "lync", "skype", "teams", "meeting", "webex", "gotomeeting",
    "adfs", "sso", "auth", "login", "signin", "register",
    "password", "reset", "forgot", "verify", "account", "profile",
    "user", "users", "member", "members", "customer", "customers",
    "partner", "partners", "vendor", "vendors", "client", "clients",
    "billing", "invoice", "payment", "pay", "checkout", "cart",
    "order", "orders", "shipping", "tracking", "returns",
    "hr", "employee", "staff", "timesheet", "payroll", "benefits",
    "intranet", "extranet", "portal2", "employee-portal",
    "hris", "workday", "successfactors", "sap", "oracle",
    "erp", "crm", "salesforce", "hubspot", "marketo", "eloqua",
    "pardot", "magento", "shopify", "woocommerce", "prestashop",
    "wordpress", "wp", "wp-admin", "wp-login", "wp-content",
    "joomla", "drupal", "moodle", "phpmyadmin", "adminer",
    "phpinfo", "info", "php", "server-status", "server-info",
    "webdav", "cgi-bin", "cpanel", "whm", "plesk", "directadmin",
    "webmin", "roundcube", "squirrelmail", "rainloop",
    "sogo", "zimbra", "zimbra-admin", "iredadmin", "postfixadmin",
    "mrtg", "cacti", "nagios", "zabbix", "icinga", "checkmk",
    "observium", "librenms", "netdata", "centreon", "splunk",
    "splunk-forwarder", "logstash-forwarder", "filebeat",
    "metricbeat", "heartbeat", "packetbeat", "auditbeat",
    "kafka", "zookeeper", "rabbitmq", "activemq", "nats",
    "consul", "etcd", "vault", "nomad", "terraform", "packer",
    "traefik", "nginx", "haproxy", "envoy", "istio", "linkerd",
    "coredns", "bind", "unbound", "pdns", "powerdns",
    "ansible", "puppet", "chef", "salt", "saltstack",
    "gitlab", "gitlab-ci", "bitbucket", "gogs", "gitea",
    "sonarqube", "sonar", "nexusiq", "harbor", "quay",
    "registry", "docker-registry", "ecr", "gcr", "acr",
    "argocd", "argocd-server", "argo-workflows", "argo-events",
    "harbor", "notary", "tuf", "clair", "trivy", "grype",
    "vulnerability", "security", "audit", "compliance",
    "iam", "identity", "access", "directory", "ldap",
    "radius", "tacacs", "freeradius", "openldap", "389ds",
    "samba", "ad", "active-directory", "domain-controller",
    "file-server", "nas", "san", "storage", "backup-server",
    "vcenter", "esxi", "vsphere", "vrealize", "vrops",
    "hyperv", "scvmm", "xenserver", "xcp-ng", "proxmox",
    "ovirt", "rhev", "virtualbox", "vmware", "vmware-vcsa",
    "jenkins-ci", "teamcity", "bamboo", "drone", "circleci",
    "travis", "codeship", "buildkite", "semaphore",
]

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 162,
    389, 443, 445, 465, 500, 514, 587, 593, 636, 873, 990, 993,
    995, 1025, 1080, 1100, 1352, 1433, 1434, 1521, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 2379,
    2380, 2443, 2483, 2484, 3000, 3128, 3306, 3389, 3690, 4000,
    4040, 4333, 4444, 4500, 4560, 4646, 4647, 4848, 5000, 5001,
    5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5038, 5222,
    5269, 5432, 5433, 5500, 5555, 5601, 5631, 5632, 5666, 5667,
    5672, 5800, 5801, 5802, 5900, 5901, 5902, 5984, 5985, 5986,
    6000, 6001, 6002, 6379, 6380, 6443, 6500, 6566, 6580, 6666,
    6667, 6668, 6669, 6697, 7000, 7001, 7002, 7070, 7071, 7080,
    7171, 7443, 7474, 7475, 7547, 7676, 7777, 7778, 8000, 8001,
    8008, 8009, 8010, 8011, 8020, 8021, 8030, 8040, 8042, 8060,
    8069, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097,
    8098, 8099, 8100, 8181, 8200, 8222, 8243, 8280, 8300, 8383,
    8400, 8403, 8443, 8500, 8530, 8531, 8686, 8800, 8834, 8880,
    8888, 8889, 8899, 8983, 9000, 9001, 9002, 9003, 9004, 9005,
    9006, 9007, 9008, 9009, 9010, 9042, 9043, 9060, 9080, 9090,
    9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100,
    9150, 9200, 9300, 9418, 9443, 9500, 9600, 9700, 9800, 9898,
    9900, 9999, 10000, 10001, 10010, 10050, 10051, 10080, 11000,
    11211, 11371, 12000, 12345, 12346, 12347, 13306, 13307,
    14000, 14141, 14142, 14143, 16010, 16020, 16030, 17000,
    18080, 18081, 18082, 18083, 18084, 18085, 18086, 18087,
    18088, 18089, 18090, 18091, 18092, 18093, 18094, 18095,
    18096, 18097, 18098, 18099, 18100, 19121, 19122, 19123,
    19124, 19125, 19126, 19127, 19128, 19129, 19130, 20000,
    21000, 22000, 22222, 23000, 24444, 24800, 25000, 25565,
    26000, 27000, 27017, 27018, 27019, 28000, 28015, 29000,
    30000, 31000, 32000, 32768, 32769, 32770, 32771, 32772,
    32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 32786, 32787, 32788,
    32789, 32790, 33060, 33061, 33062, 33063, 33064, 33065,
    33066, 33067, 33068, 33069, 33070, 33333, 40000, 41000,
    42000, 43000, 44000, 45000, 49152, 49153, 49154, 49155,
    49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163,
    49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171,
    49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179,
    49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187,
    49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195,
    49196, 49197, 49198, 49199, 49200, 50000, 50001, 50002,
    50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010,
    50070, 50075, 50090, 50095, 51000, 52000, 53000, 54000,
    55000, 55555, 56000, 57000, 58000, 59000, 60000, 60010,
    60020, 60030, 60040, 60050, 60060, 60070, 60080, 60090,
    60100, 61000, 62000, 63000, 64000, 65000, 65535,
]

# 不安全的 / 需要特别关注的端口列表
HIGH_VALUE_PORTS = [21, 22, 23, 3389, 3306, 1433, 5432, 6379, 27017, 5900, 8080, 8443, 9200, 9300, 50000]


# ============================================================
# 工具函数
# ============================================================
def set_socket_timeout(timeout=SOCKET_TIMEOUT):
    """设置全局 socket 超时"""
    socket.setdefaulttimeout(timeout)


def resolve_domain_simple(hostname):
    """简单 DNS 解析，返回 IP 或 None"""
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, OSError):
        return None


def resolve_domain_dnspython(hostname):
    """使用 dnspython 进行 DNS A 记录解析，返回 IP 列表"""
    try:
        answers = dns_resolver.resolve(hostname, "A")
        return [str(a) for a in answers]
    except (dns_exception.DNSException, dns_resolver.NoAnswer,
            dns_resolver.NXDOMAIN, dns_resolver.NoNameservers,
            dns_resolver.Timeout, OSError):
        return []


def is_private_ip(ip):
    """判断是否为私有 IP 地址"""
    try:
        parts = [int(p) for p in ip.split(".")]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
        if parts[0] == 0:
            return True
        # 链路本地地址 169.254.x.x
        if parts[0] == 169 and parts[1] == 254:
            return True
        # 多播地址
        if 224 <= parts[0] <= 239:
            return True
        return False
    except (ValueError, IndexError):
        return True  # 无法解析视为私有


def check_wildcard_dns(domain):
    """
    泛解析检测：随机生成一个不可能存在的子域名前缀，看是否解析到 IP
    返回 (has_wildcard, wildcard_ips)
    """
    test_prefix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12))
    test_host = f"{test_prefix}.{domain}"
    try:
        ips = resolve_domain_dnspython(test_host)
        if ips:
            return True, ips
        # 再试一次用 gethostbyname
        ip = resolve_domain_simple(test_host)
        if ip:
            return True, [ip]
        return False, []
    except Exception:
        return False, []


def filter_wildcard_subdomains(domains, wildcard_ips):
    """
    过滤泛解析产生的"假"子域名
    如果子域名解析到的 IP 完全包含在泛解析 IP 集合中，则视为泛解析结果，过滤掉
    """
    if not wildcard_ips:
        return domains
    wildcard_set = set(wildcard_ips)
    filtered = []
    for host in domains:
        ips = resolve_domain_dnspython(host)
        if ips:
            # 如果解析到的 IP 全部在泛解析 IP 中，可能是泛解析
            if set(ips).issubset(wildcard_set):
                continue
        filtered.append(host)
    return filtered


# ============================================================
# 主扫描器类
# ============================================================
class SubdomainScanner:
    """子域名资产扫描器"""

    def __init__(self, domain, threads=10, ports=None, dict_path=None,
                 no_c=False, no_p=False, no_u=False, no_wildcard=False,
                 output_dir=None, timeout=SOCKET_TIMEOUT, http_timeout=HTTP_TIMEOUT):
        self.domain = domain.strip().lower()
        self.threads = max(1, int(threads))
        self.ports = ports if ports else DEFAULT_PORTS
        self.sub_dict = self._load_dict(dict_path)
        self.scan_c = not no_c
        self.scan_p = not no_p
        self.scan_u = not no_u
        self.skip_wildcard = no_wildcard  # True: 跳过泛解析检测 (默认进行)
        self.socket_timeout = timeout
        self.http_timeout = http_timeout

        # 设置全局超时
        set_socket_timeout(self.socket_timeout)

        # ---- 结果存储 ----
        self.valid_subdomains = []       # 有效子域名列表
        self.dns_result = {}             # {subdomain: [ip1, ip2, ...]}
        self.c_networks = set()          # C 段集合 (如 192.168.1)
        self.c_alive_ips = []            # C 段存活 IP
        self.port_result = {}            # {ip: [port1, port2, ...]}
        self.url_result = {}             # {subdomain: {status, absolute_urls, relative_urls}}
        self.wildcard_ips = []           # 泛解析 IP 列表
        self.has_wildcard = False        # 是否存在泛解析

        # ---- 统计信息 ----
        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_subdomains_checked": 0,
            "valid_subdomains_count": 0,
            "total_ips_resolved": 0,
            "c_networks_count": 0,
            "c_alive_count": 0,
            "ports_open_count": 0,
            "urls_extracted_count": 0,
        }

        # ---- 创建输出目录 ----
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_dir:
            self.result_dir = output_dir
        else:
            self.result_dir = f"result_{self.domain}_{timestamp}"
        os.makedirs(self.result_dir, exist_ok=True)

        # ---- 锁 ----
        self._lock = threading.Lock()

    def _load_dict(self, path):
        """加载子域名字典"""
        if path:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    if lines:
                        print(f"[+] 加载字典文件: {path} ({len(lines)} 条)")
                        return lines
                    else:
                        print(f"[!] 字典文件为空: {path}，使用默认字典")
                except Exception as e:
                    print(f"[!] 读取字典文件失败: {e}，使用默认字典")
            else:
                print(f"[!] 字典文件不存在: {path}，使用默认字典")
        print(f"[+] 使用内置默认字典 ({len(DEFAULT_SUBDOMAINS)} 条)")
        return DEFAULT_SUBDOMAINS

    # ==================== 步骤1: 子域名探测 ====================
    def subdomain_scan(self):
        """多线程子域名爆破"""
        print("\n" + "=" * 60)
        print(f"  步骤 1/5: 子域名探测 (Subdomain Discovery)")
        print(f"  目标域名: {self.domain}")
        print(f"  字典数量: {len(self.sub_dict)}")
        print(f"  线程数: {self.threads}")
        print("=" * 60)

        # 泛解析检测
        if not self.skip_wildcard:
            print("[*] 检测泛解析 (Wildcard DNS)...", end=" ", flush=True)
            self.has_wildcard, self.wildcard_ips = check_wildcard_dns(self.domain)
            if self.has_wildcard:
                print(f"发现泛解析! 样本 IP: {self.wildcard_ips[:3]}")
                print("[*] 将在 DNS 解析步骤后进行泛解析过滤")
            else:
                print("未发现泛解析")
        else:
            print("[*] 已跳过泛解析检测")

        all_subdomains = [f"{sub}.{self.domain}" for sub in self.sub_dict]
        valid = []
        total = len(all_subdomains)

        # 任务队列
        q = queue.Queue()
        for host in all_subdomains:
            q.put(host)

        # 线程安全计数器
        checked_counter = [0]
        found_counter = [0]
        lock = threading.Lock()

        start_time = time.time()

        # 进度条
        pbar = tqdm(total=total, desc="子域名探测", unit="个", ncols=80, ascii=True)

        def worker():
            """工作线程"""
            while True:
                try:
                    host = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    ip = resolve_domain_simple(host)
                    with lock:
                        checked_counter[0] += 1
                        pbar.update(1)
                        if ip:
                            valid.append(host)
                            found_counter[0] += 1
                            # 动态显示最新的发现（不影响进度条格式）
                            pbar.set_postfix_str(f"发现: {found_counter[0]}", refresh=False)
                except Exception:
                    with lock:
                        checked_counter[0] += 1
                        pbar.update(1)
                finally:
                    q.task_done()

        # 启动线程
        workers = []
        for _ in range(min(self.threads, total)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        # 等待所有任务完成
        q.join()
        for t in workers:
            t.join()

        pbar.close()

        elapsed = time.time() - start_time
        self.valid_subdomains = valid
        self.stats["total_subdomains_checked"] = total
        self.stats["valid_subdomains_count"] = len(valid)

        print(f"\n[+] 子域名探测完成!")
        print(f"    - 检测数量: {total}")
        print(f"    - 发现数量: {len(valid)}")
        print(f"    - 用时: {elapsed:.2f}s")

        # 保存结果
        self._save_text("1_subdomains.txt", valid)
        print(f"    - 已保存: {self.result_dir}/1_subdomains.txt")

    # ==================== 步骤2: DNS 解析 ====================
    def dns_resolve(self):
        """DNS A 记录解析"""
        print("\n" + "=" * 60)
        print(f"  步骤 2/5: DNS 解析 (DNS Resolution)")
        print(f"  待解析域名: {len(self.valid_subdomains)}")
        print("=" * 60)

        if not self.valid_subdomains:
            print("[!] 没有子域名需要解析")
            self.dns_result = {}
            return

        dns_result = {}
        total = len(self.valid_subdomains)
        pbar = tqdm(total=total, desc="DNS 解析", unit="个", ncols=80, ascii=True)

        def worker(host):
            ips = resolve_domain_dnspython(host)
            return host, ips

        with ThreadPoolExecutor(max_workers=min(self.threads, total)) as executor:
            futures = {executor.submit(worker, host): host for host in self.valid_subdomains}
            for future in as_completed(futures):
                host, ips = future.result()
                dns_result[host] = ips
                pbar.update(1)

        pbar.close()

        self.dns_result = dns_result

        # 泛解析过滤：如果存在泛解析，过滤掉解析到泛解析 IP 的子域名
        if self.has_wildcard and self.wildcard_ips:
            print("[*] 进行泛解析过滤...")
            filtered = {}
            for host, ips in dns_result.items():
                if ips and set(ips).issubset(set(self.wildcard_ips)):
                    continue
                filtered[host] = ips
            self.dns_result = filtered
            removed_count = len(dns_result) - len(filtered)
            if removed_count > 0:
                print(f"    - 过滤掉 {removed_count} 个泛解析子域名")
            # 同步更新 valid_subdomains
            self.valid_subdomains = list(filtered.keys())
            self.stats["valid_subdomains_count"] = len(self.valid_subdomains)

        # 统计有 IP 的域名数
        resolved_count = sum(1 for ips in self.dns_result.values() if ips)
        total_ips = sum(len(ips) for ips in self.dns_result.values())
        self.stats["total_ips_resolved"] = total_ips

        # 保存结果
        self._save_json("2_dns.json", self.dns_result)

        print(f"\n[+] DNS 解析完成!")
        print(f"    - 解析成功: {resolved_count}/{len(self.dns_result)}")
        print(f"    - 共获取 IP: {total_ips} 个")
        print(f"    - 已保存: {self.result_dir}/2_dns.json")

    # ==================== 步骤3: C 段扫描 ====================
    def c_scan(self):
        """IP C 段存活扫描"""
        if not self.scan_c:
            print("\n[+] 已跳过 C 段扫描 (--no-c)")
            return

        print("\n" + "=" * 60)
        print(f"  步骤 3/5: C 段扫描 (C Segment Scan)")
        print("=" * 60)

        # 收集所有 IP
        all_ips = []
        for ips in self.dns_result.values():
            all_ips.extend(ips)
        all_ips = list(set([ip for ip in all_ips if ip]))

        if not all_ips:
            print("[!] 没有 IP 可用于 C 段扫描")
            return

        # 提取 C 段
        c_networks = set()
        for ip in all_ips:
            try:
                parts = ip.split(".")
                c = f"{parts[0]}.{parts[1]}.{parts[2]}"
                c_networks.add(c)
            except (IndexError, ValueError):
                continue

        self.c_networks = c_networks
        self.stats["c_networks_count"] = len(c_networks)

        print(f"    - 源 IP 数: {len(all_ips)}")
        print(f"    - 涉及 C 段: {len(c_networks)} 个")
        for c in sorted(c_networks):
            print(f"      {c}.0/24")
        print(f"    - 开始扫描 {len(c_networks) * 254} 个 IP...")

        # 扫描存活 IP
        alive_ips = []
        total = len(c_networks) * 254
        pbar = tqdm(total=total, desc="C 段扫描", unit="个", ncols=80, ascii=True)
        lock = threading.Lock()

        q = queue.Queue()
        for c in c_networks:
            for i in range(1, 255):
                q.put(f"{c}.{i}")

        def worker():
            while True:
                try:
                    host = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    # 使用快速 socket 连接测试 + gethostbyname_ex
                    ip = resolve_domain_simple(host)
                    with lock:
                        pbar.update(1)
                        if ip:
                            # 再尝试一次反向解析确认
                            try:
                                hostname, _, _ = socket.gethostbyaddr(ip)
                                alive_ips.append(host)
                            except (socket.herror, socket.timeout, OSError):
                                # 没有 PTR 记录但 IP 可达也算
                                alive_ips.append(host)
                except Exception:
                    with lock:
                        pbar.update(1)
                finally:
                    q.task_done()

        # 启动线程（C 段扫描使用较少的线程，避免被误判为攻击）
        scan_threads = min(self.threads, 50)
        workers = []
        for _ in range(scan_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        q.join()
        for t in workers:
            t.join()

        pbar.close()

        self.c_alive_ips = sorted(set(alive_ips))
        self.stats["c_alive_count"] = len(self.c_alive_ips)

        # 保存结果
        self._save_text("3_c_alive.txt", self.c_alive_ips)

        print(f"\n[+] C 段扫描完成!")
        print(f"    - 扫描 IP 数: {total}")
        print(f"    - 存活主机: {len(self.c_alive_ips)}")
        print(f"    - 已保存: {self.result_dir}/3_c_alive.txt")

    # ==================== 步骤4: 端口扫描 ====================
    def port_scan(self):
        """多线程 TCP 端口扫描"""
        if not self.scan_p:
            print("\n[+] 已跳过端口扫描 (--no-p)")
            return

        print("\n" + "=" * 60)
        print(f"  步骤 4/5: 端口扫描 (Port Scan)")
        print(f"  目标端口数: {len(self.ports)}")
        print("=" * 60)

        # 收集所有待扫描的 IP
        target_ips = set()
        for ips in self.dns_result.values():
            target_ips.update(ips)
        target_ips.update(self.c_alive_ips)
        target_ips = [ip for ip in target_ips if ip]

        # 过滤私有 IP（除非用户在命令行强制指定了）
        # 但这里我们保留私有 IP，因为内网资产也可能有价值
        # 只是给出提示
        private_count = sum(1 for ip in target_ips if is_private_ip(ip))
        if private_count > 0:
            print(f"    [!] 包含 {private_count} 个私有 IP (内网地址)")

        if not target_ips:
            print("[!] 没有目标 IP 可用于端口扫描")
            return

        print(f"    - 目标 IP 数: {len(target_ips)}")
        print(f"    - 端口数: {len(self.ports)}")
        print(f"    - 总扫描任务数: {len(target_ips) * len(self.ports)}")

        port_result = {}
        lock = threading.Lock()
        total_tasks = len(target_ips) * len(self.ports)
        completed = [0]

        # 构建扫描队列
        q = queue.Queue()
        for ip in target_ips:
            for port in self.ports:
                q.put((ip, port))

        pbar = tqdm(total=total_tasks, desc="端口扫描", unit="个", ncols=80, ascii=True)

        def worker():
            while True:
                try:
                    ip, port = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.socket_timeout)
                    result = s.connect_ex((ip, port))
                    s.close()
                    with lock:
                        completed[0] += 1
                        pbar.update(1)
                        if result == 0:
                            if ip not in port_result:
                                port_result[ip] = []
                            port_result[ip].append(port)
                except Exception:
                    with lock:
                        completed[0] += 1
                        pbar.update(1)
                finally:
                    q.task_done()

        scan_threads = min(self.threads, 200)
        workers = []
        for _ in range(scan_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        q.join()
        for t in workers:
            t.join()

        pbar.close()

        self.port_result = port_result
        open_ports_count = sum(len(ports) for ports in port_result.values())
        self.stats["ports_open_count"] = open_ports_count

        # 保存结果
        self._save_json("4_ports.json", port_result)

        print(f"\n[+] 端口扫描完成!")
        print(f"    - 扫描完成: {total_tasks}")
        print(f"    - 发现开放端口: {open_ports_count}")
        print(f"    - 受影响 IP: {len(port_result)}")
        print(f"    - 已保存: {self.result_dir}/4_ports.json")

        # 额外报告高价值端口
        high_value_found = {}
        for ip, ports in port_result.items():
            hv = [p for p in ports if p in HIGH_VALUE_PORTS]
            if hv:
                high_value_found[ip] = hv
        if high_value_found:
            print(f"\n    [!] 高风险端口提醒:")
            for ip, ports in sorted(high_value_found.items()):
                print(f"        {ip}: {', '.join(f'{p}' for p in sorted(ports))}")

    # ==================== 步骤5: URL 提取 ====================
    def url_extract(self):
        """HTTP 请求 + URL 提取"""
        if not self.scan_u:
            print("\n[+] 已跳过 URL 提取 (--no-u)")
            return

        print("\n" + "=" * 60)
        print(f"  步骤 5/5: URL 提取 (URL Extraction)")
        print(f"  目标子域名: {len(self.valid_subdomains)}")
        print("=" * 60)

        if not self.valid_subdomains:
            print("[!] 没有子域名可用于 URL 提取")
            return

        # 编译正则
        abs_url_pattern = re.compile(
            r'https?://(?:[-\w.]|%[\da-fA-F]{2})+(?::\d+)?(?:/[^\s"\'<>()\[\]{}]*)?'
        )
        # href / src / action 属性提取
        attr_pattern = re.compile(
            r'''(?:href|src|action|data-src|data-href)=["']([^"']+)["']''',
            re.I
        )
        # 也匹配 url() CSS 函数
        css_url_pattern = re.compile(
            r'url\(["\']?([^"\'()]+)["\']?\)',
            re.I
        )

        url_result = {}
        total = len(self.valid_subdomains)
        pbar = tqdm(total=total, desc="URL 提取", unit="个", ncols=80, ascii=True)
        lock = threading.Lock()
        success_count = [0]

        def worker(host):
            """对单个子域名进行 HTTP 请求并提取 URL"""
            record = {"status": "error", "absolute_urls": [], "relative_urls": []}
            abs_set = set()
            rel_set = set()

            urls_to_try = [f"http://{host}", f"https://{host}"]

            for url in urls_to_try:
                try:
                    resp = requests.get(
                        url,
                        headers={"User-Agent": USER_AGENT},
                        timeout=self.http_timeout,
                        verify=False,
                        allow_redirects=True,
                    )
                    html = resp.text[:MAX_RESPONSE_BYTES]
                    final_url = resp.url
                    base_url = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"

                    record["status"] = resp.status_code

                    # ---- 提取绝对 URL ----
                    for match in abs_url_pattern.finditer(html):
                        url_str = match.group(0).rstrip(".,;:!?)]}'\"")
                        if url_str.startswith(("http://", "https://")):
                            abs_set.add(url_str)

                    # ---- 提取属性中的 URL ----
                    for match in attr_pattern.finditer(html):
                        path = match.group(1).strip()
                        if not path or path.startswith("#") or path.startswith("javascript:"):
                            continue
                        if path.startswith(("http://", "https://")):
                            abs_set.add(path)
                        elif path.startswith("//"):
                            abs_set.add(f"https:{path}")
                        elif path.startswith("/"):
                            rel_set.add(path)
                        else:
                            # 相对路径，不补全为绝对路径，保留原始值
                            rel_set.add(path)

                    # ---- 提取 CSS url() ----
                    for match in css_url_pattern.finditer(html):
                        path = match.group(1).strip().strip("'\"")
                        if not path:
                            continue
                        if path.startswith(("http://", "https://")):
                            abs_set.add(path)
                        elif path.startswith("//"):
                            abs_set.add(f"https:{path}")
                        elif path.startswith("/"):
                            rel_set.add(path)
                        elif path.startswith("data:"):
                            continue

                    # ---- 提取 <form> 的 action ----
                    form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.I)
                    for match in form_pattern.finditer(html):
                        path = match.group(1).strip()
                        if path.startswith(("http://", "https://")):
                            abs_set.add(path)
                        elif path.startswith("//"):
                            abs_set.add(f"https:{path}")
                        elif path.startswith("/"):
                            rel_set.add(path)

                    # 成功获取后只尝试一次
                    break

                except requests.exceptions.SSLError:
                    # SSL 错误时尝试下一个 URL (http)
                    continue
                except (requests.exceptions.ConnectionError,
                        requests.exceptions.Timeout,
                        requests.exceptions.RequestException):
                    continue
                except Exception:
                    continue

            record["absolute_urls"] = sorted(abs_set)
            record["relative_urls"] = sorted(rel_set)

            with lock:
                url_result[host] = record
                if record["status"] != "error":
                    success_count[0] += 1
                pbar.update(1)

            return host, record

        with ThreadPoolExecutor(max_workers=min(self.threads, total, 50)) as executor:
            futures = {executor.submit(worker, host): host for host in self.valid_subdomains}
            for future in as_completed(futures):
                future.result()  # 确保异常被捕获

        pbar.close()

        self.url_result = url_result
        total_urls = sum(
            len(v.get("absolute_urls", [])) + len(v.get("relative_urls", []))
            for v in url_result.values()
        )
        self.stats["urls_extracted_count"] = total_urls

        # 保存结果
        self._save_json("5_urls.json", url_result)

        print(f"\n[+] URL 提取完成!")
        print(f"    - 请求成功: {success_count[0]}/{total}")
        print(f"    - 共提取 URL: {total_urls} 个")
        print(f"      - 绝对 URL: {sum(len(v.get('absolute_urls', [])) for v in url_result.values())}")
        print(f"      - 相对 URL: {sum(len(v.get('relative_urls', [])) for v in url_result.values())}")
        print(f"    - 已保存: {self.result_dir}/5_urls.json")

    # ==================== 保存辅助 ====================
    def _save_text(self, filename, lines):
        """保存文本列表到文件"""
        path = os.path.join(self.result_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(str(x) for x in lines))
        except Exception as e:
            print(f"[!] 保存文件失败 {filename}: {e}")

    def _save_json(self, filename, data):
        """保存 JSON 数据到文件"""
        path = os.path.join(self.result_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[!] 保存 JSON 失败 {filename}: {e}")

    # ==================== 生成总结报告 ====================
    def _generate_summary(self):
        """生成扫描总结报告 (Markdown)"""
        lines = []
        lines.append(f"# 子域名资产扫描报告: {self.domain}")
        lines.append(f"")
        lines.append(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**结果目录**: `{self.result_dir}`")
        lines.append(f"")
        lines.append("## 扫描结果概览")
        lines.append("")
        lines.append("| 阶段 | 状态 | 数量 |")
        lines.append("|------|------|------|")
        lines.append(
            f"| 子域名探测 | {'✓' if self.stats['valid_subdomains_count'] > 0 else '✗'} "
            f"| {self.stats['valid_subdomains_count']}/{self.stats['total_subdomains_checked']} |"
        )
        lines.append(
            f"| DNS 解析 | {'✓' if self.stats['total_ips_resolved'] > 0 else '✗'} "
            f"| {self.stats['total_ips_resolved']} 个 IP |"
        )
        lines.append(
            f"| C 段扫描 | {'✓ (已启用)' if self.scan_c else '✗ (已跳过)'} "
            f"| {self.stats['c_alive_count']} 个存活 |"
        )
        lines.append(
            f"| 端口扫描 | {'✓ (已启用)' if self.scan_p else '✗ (已跳过)'} "
            f"| {self.stats['ports_open_count']} 个端口开放 |"
        )
        lines.append(
            f"| URL 提取 | {'✓ (已启用)' if self.scan_u else '✗ (已跳过)'} "
            f"| {self.stats['urls_extracted_count']} 个 URL |"
        )
        lines.append("")

        if self.dns_result:
            lines.append("## DNS 解析结果")
            lines.append("")
            lines.append("| 子域名 | IP 地址 |")
            lines.append("|--------|---------|")
            for host in sorted(self.dns_result.keys()):
                ips = self.dns_result[host]
                if ips:
                    lines.append(f"| {host} | {', '.join(ips)} |")
                else:
                    lines.append(f"| {host} | (解析失败) |")
            lines.append("")

        if self.port_result:
            lines.append("## 端口扫描结果")
            lines.append("")
            lines.append("| IP | 开放端口 |")
            lines.append("|----|---------|")
            for ip in sorted(self.port_result.keys()):
                ports = sorted(self.port_result[ip])
                ports_str = ", ".join(f"{p}" for p in ports)
                lines.append(f"| {ip} | {ports_str} |")
            lines.append("")

        if self.url_result:
            lines.append("## URL 提取摘要")
            lines.append("")
            lines.append("| 子域名 | 状态 | 绝对 URL 数 | 相对 URL 数 |")
            lines.append("|--------|------|------------|------------|")
            for host in sorted(self.url_result.keys()):
                rec = self.url_result[host]
                lines.append(
                    f"| {host} | {rec.get('status', 'error')} "
                    f"| {len(rec.get('absolute_urls', []))} "
                    f"| {len(rec.get('relative_urls', []))} |"
                )
            lines.append("")

        lines.append("---")
        lines.append(f"*由子域名资产扫描工具 v1.0 自动生成*")

        return "\n".join(lines)

    def _save_summary(self):
        """保存总结报告"""
        summary = self._generate_summary()
        path = os.path.join(self.result_dir, "SUMMARY.md")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(summary)
            print(f"    - 总结报告: {path}")
        except Exception as e:
            print(f"[!] 保存总结报告失败: {e}")

    # ==================== 运行流程 ====================
    def run(self):
        """执行全流程扫描"""
        self.stats["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("╔" + "═" * 58 + "╗")
        print("║           子域名资产扫描工具 v1.0               ║")
        print("║        Subdomain Asset Scanner                  ║")
        print("╚" + "═" * 58 + "╝")
        print(f"  目标域名: {self.domain}")
        print(f"  结果目录: {self.result_dir}")
        print(f"  开始时间: {self.stats['start_time']}")
        print(f"  功能状态:")
        print(f"    - C 段扫描: {'✓' if self.scan_c else '✗'}")
        print(f"    - 端口扫描: {'✓' if self.scan_p else '✗'}")
        print(f"    - URL 提取: {'✓' if self.scan_u else '✗'}")
        print(f"    - 泛解析检测: {'✗ (已跳过)' if self.skip_wildcard else '✓'}")

        start_all = time.time()

        # 按顺序执行各步骤
        self.subdomain_scan()
        self.dns_resolve()
        self.c_scan()
        self.port_scan()
        self.url_extract()
        self._save_summary()

        total_elapsed = time.time() - start_all
        self.stats["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 打印最终总结
        print("\n" + "=" * 60)
        print("  [✓] 全流程扫描完成!")
        print(f"  总用时: {total_elapsed:.2f}s ({total_elapsed/60:.1f}min)")
        print(f"  结果目录: {self.result_dir}")
        print("=" * 60)
        print()
        print("  📊 扫描统计:")
        print(f"    - 发现子域名: {self.stats['valid_subdomains_count']}")
        print(f"    - 解析到 IP:  {self.stats['total_ips_resolved']} 个地址")
        print(f"    - C 段存活:   {self.stats['c_alive_count']} 台主机")
        print(f"    - 开放端口:   {self.stats['ports_open_count']} 个端口")
        print(f"    - 提取 URL:   {self.stats['urls_extracted_count']} 个链接")
        print()
        print("  📁 输出文件:")
        print(f"    - 1_subdomains.txt  (子域名列表)")
        print(f"    - 2_dns.json        (DNS 映射)")
        print(f"    - 3_c_alive.txt     (C 段存活)")
        print(f"    - 4_ports.json      (端口扫描)")
        print(f"    - 5_urls.json       (URL 提取)")
        print(f"    - SUMMARY.md        (总结报告)")
        print()
        print("  💡 提示: 使用 --no-c --no-p --no-u 可跳过不需要的步骤")


# ============================================================
# 命令行入口
# ============================================================
def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="子域名资产扫描工具 v1.0 - 完整的子域名资产探测与信息收集工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python subdomain_scanner.py -d example.com
  python subdomain_scanner.py -d example.com -f subdomains.txt -t 100
  python subdomain_scanner.py -d example.com --no-c --no-p --no-u
  python subdomain_scanner.py -d example.com -p 80 443 8080 8443
  python subdomain_scanner.py -d example.com -o ./my_scan_results
        """
    )

    # 必需参数
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="目标域名，例如: example.com"
    )

    # 可选参数
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="并发线程数 (默认: 50)"
    )

    parser.add_argument(
        "-p", "--ports",
        type=int,
        nargs="+",
        default=None,
        help="自定义端口列表，例如: 80 443 8080 (默认使用常用端口列表)"
    )

    parser.add_argument(
        "-f", "--file",
        default=None,
        help="子域名字典文件路径 (每行一个子域名)"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="输出目录 (默认自动生成)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=SOCKET_TIMEOUT,
        help=f"Socket 超时秒数 (默认: {SOCKET_TIMEOUT}s)"
    )

    parser.add_argument(
        "--http-timeout",
        type=float,
        default=HTTP_TIMEOUT,
        help=f"HTTP 请求超时秒数 (默认: {HTTP_TIMEOUT}s)"
    )

    # 模块开关
    parser.add_argument(
        "--no-c",
        action="store_true",
        help="跳过 C 段扫描"
    )

    parser.add_argument(
        "--no-p",
        action="store_true",
        help="跳过端口扫描"
    )

    parser.add_argument(
        "--no-u",
        action="store_true",
        help="跳过 URL 提取"
    )

    parser.add_argument(
        "--no-wildcard",
        action="store_true",
        help="跳过泛解析检测 (默认进行泛解析检测)"
    )

    # 版本信息
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="子域名资产扫描工具 v1.0",
        help="显示版本信息"
    )

    return parser.parse_args()


def main():
    """主函数"""
    args = parse_args()

    # 参数校验
    if not args.domain:
        print("[!] 错误: 必须指定目标域名 (-d / --domain)")
        sys.exit(1)

    # 如果指定了自定义端口，验证端口合法性
    if args.ports:
        valid_ports = []
        for p in args.ports:
            if 1 <= p <= 65535:
                valid_ports.append(p)
            else:
                print(f"[!] 警告: 忽略无效端口 {p}，端口范围 1-65535")
        if not valid_ports:
            print("[!] 错误: 没有有效的端口")
            sys.exit(1)
        args.ports = valid_ports

    # 创建扫描器
    scanner = SubdomainScanner(
        domain=args.domain,
        threads=args.threads,
        ports=args.ports,
        dict_path=args.file,
        no_c=args.no_c,
        no_p=args.no_p,
        no_u=args.no_u,
        no_wildcard=args.no_wildcard,
        output_dir=args.output,
        timeout=args.timeout,
        http_timeout=args.http_timeout,
    )

    # 开始扫描
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断扫描!")
        print("[*] 已完成的步骤结果已保存")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] 扫描过程出现未预期错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()