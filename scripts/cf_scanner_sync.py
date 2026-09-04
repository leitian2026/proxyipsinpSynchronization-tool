import os
import random
import time
import re
import requests
import concurrent.futures
from datetime import datetime, timedelta, timezone

DEFAULT_REGIONS = "SJC"
SYNC_MAIN_DOMAIN = "NO"

def load_cf_cidrs(file_path="ip.txt"):
    if not os.path.exists(file_path):
        print(f"Error: 找不到 {file_path} 文件！")
        exit(1)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            cidrs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        if not cidrs:
            print(f"Error: {file_path} 文件为空！")
            exit(1)
        return cidrs
    except Exception as e:
        print(f"Error: 读取 {file_path} 失败: {e}")
        exit(1)

CF_CIDRS = load_cf_cidrs()

def generate_random_ip(hot_cidrs=None):
    for _ in range(10):
        try:
            if hot_cidrs and random.random() < 0.5:
                cidr = random.choice(hot_cidrs)
            else:
                cidr = random.choice(CF_CIDRS)
            if '/' in cidr:
                base_ip, prefix = cidr.split('/')
                prefix = int(prefix)
            else:
                base_ip = cidr
                prefix = 32
            parts = list(map(int, base_ip.split('.')))
            if len(parts) != 4:
                continue
            ip_long = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
            host_bits = 32 - prefix
            mask = (1 << host_bits) - 1
            random_host = random.randint(0, mask)
            final_ip_long = (ip_long & ~mask) | random_host
            p1 = (final_ip_long >> 24) & 255
            p2 = (final_ip_long >> 16) & 255
            p3 = (final_ip_long >> 8) & 255
            p4 = final_ip_long & 255
            return f"{p1}.{p2}.{p3}.{p4}"
        except Exception:
            continue
    return "1.1.1.1"

def _to_int(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        m = re.search(r"(\d+)", v)
        if m:
            return int(m.group(1))
    return None

def test_ip(ip, check_api_url, check_api_key="", timeout=5.0):
    start_time = time.time()
    try:
        # 兼容 nyc.mn 和你自建的 yp.myoo.ccwu.cc / velvet-xxxx
        # nyc.mn 用 token，你自建的用 key，都带上最稳
        url = f"{check_api_url}?proxyip={ip}"
        if check_api_key:
            url += f"&token={check_api_key}&key={check_api_key}"

        resp = requests.get(url, timeout=timeout)
        # 有些被 CF 拦的会返回非 JSON，直接抛异常进 except
        data = resp.json()

        # 你的 worker.js / nyc.mn 成功时 success=True
        # 失败时可能是 {"success":False,"error":"TCP Loop detected"} 或 Cloudflare IP blocked
        if data.get("success") is True:
            connect_time = int((time.time() - start_time) * 1000)
            colo = data.get("dataCenter") or data.get("colo") or data.get("country") or "UNK"
            latency = (
                _to_int(data.get("responseTime")) or
                _to_int(data.get("latencyMs")) or
                _to_int(data.get("tcpDuration")) or
                _to_int(data.get("latency")) or
                connect_time
            )
            return {"ip": ip, "latency": latency, "colo": colo}
        else:
            # 调试用，扫不出时打开这行看原因：TCP Loop / Cloudflare IP blocked 就是被 CF 拦了
            # print(f"[FAIL] {ip} -> {data}")
            return None
    except Exception as e:
        # print(f"[ERROR] {ip} -> {e}")
        return None

def sync_to_cloudflare(api_token, zone_id, target_domain, best_ips, cf_email):
    headers = {
        "X-Auth-Email": cf_email,
        "X-Auth-Key": api_token,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={target_domain}"
    print(f"Fetching existing DNS records for {target_domain}...")
    try:
        resp = requests.get(url, headers=headers).json()
        if not resp.get("success"):
            print("Failed to fetch DNS records:", resp)
            return False
        existing_records = resp.get("result", [])
        existing_map = {r["content"]: r["id"] for r in existing_records}
        desired_ips = [ip["ip"] for ip in best_ips]
        for ip_val, record_id in existing_map.items():
            if ip_val not in desired_ips:
                print(f"Deleting outdated IP: {ip_val}")
                del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
                requests.delete(del_url, headers=headers)
        for ip_val in desired_ips:
            if ip_val not in existing_map:
                print(f"Adding new IP: {ip_val}")
                post_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                data = {
                    "type": "A",
                    "name": target_domain,
                    "content": ip_val,
                    "ttl": 60,
                    "proxied": False
                }
                requests.post(post_url, headers=headers, json=data)
        print("Cloudflare DNS Sync completed successfully!")
        return True
    except Exception as e:
        print(f"Exception during Cloudflare sync: {e}")
        return False

def save_ips_to_file(best_ips):
    bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
    with open("ips-v4.txt", "w", encoding="utf-8") as f:
        for ip in best_ips:
            f.write(f"{ip['ip']}#{ip['colo']}\n")
    print("Successfully saved latest IPs to ips-v4.txt")

def main():
    api_token = os.environ.get("CF_API_TOKEN")
    zone_id = os.environ.get("CF_ZONE_ID")
    base_domain = os.environ.get("CF_TARGET_DOMAIN")
    cf_email = os.environ.get("CF_EMAIL")
    region_input = DEFAULT_REGIONS
    target_regions = [r.strip().upper() for r in region_input.split(",") if r.strip()]
    is_scan_all = "ALL" in target_regions
    if is_scan_all:
        print(f"Target Regions dynamically set to: ALL (Global Scan Mode)")
    else:
        print(f"Target Regions dynamically set to: {target_regions}")

    # 关键：这里默认用 nyc.mn 这种 fetch 版的接口才能测 CF IP
    # 如果你用 velvet-xxxx 这种 connect() 版的，测 104.21.x.x 必被 CF 拦成 0
    # 你自建的 yp.myoo.ccwu.cc 也是 fetch 版，可以填它：https://yp.myoo.ccwu.cc
    check_api_url = os.environ.get("CHECK_API_URL", "https://check.proxyip.cmliussss.net/check")
    check_api_key = os.environ.get("CHECK_API_KEY", "")
    sync_count = int(os.environ.get("SYNC_COUNT", 10))
    scan_count = int(os.environ.get("SCAN_COUNT", 2000))

    hot_cidrs = []
    if os.path.exists("ips-v4.txt"):
        try:
            with open("ips-v4.txt", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ip_str = line.split("#")[0]
                        parts = ip_str.split(".")
                        if len(parts) == 4:
                            hot_cidrs.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
            hot_cidrs = list(set(hot_cidrs))
            print(f"Loaded {len(hot_cidrs)} hot /24 subnets from ips-v4.txt")
        except Exception:
            pass

    can_sync = True
    if not all([api_token, zone_id, base_domain, cf_email]):
        print("Warning: Missing CF env vars, DNS sync will be skipped")
        can_sync = False

    print(f"Generating {scan_count} random Cloudflare IPs...")
    valid_ips_by_region = {}
    if not is_scan_all:
        valid_ips_by_region = {region: [] for region in target_regions}

    max_attempts = 5
    attempt = 0
    ALL_MODE_LIMIT = 20

    while attempt < max_attempts:
        total_collected = sum(len(ips) for ips in valid_ips_by_region.values())
        if is_scan_all and total_collected >= ALL_MODE_LIMIT:
            break
        elif not is_scan_all and all(len(ips) >= sync_count for ips in valid_ips_by_region.values()):
            break
        attempt += 1
        print(f"--- Scan Iteration {attempt} ---")
        ips_to_test = [generate_random_ip(hot_cidrs) for _ in range(scan_count)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(test_ip, ip, check_api_url, check_api_key): ip for ip in ips_to_test}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    colo = result.get('colo', 'UNK').upper()
                    if colo != 'UNK' and (is_scan_all or colo in target_regions):
                        if colo not in valid_ips_by_region:
                            valid_ips_by_region[colo] = []
                        if is_scan_all:
                            total_collected = sum(len(ips) for ips in valid_ips_by_region.values())
                            if total_collected < ALL_MODE_LIMIT:
                                valid_ips_by_region[colo].append(result)
                                print(f"[FOUND {colo}] {result['ip']} (Total ALL: {total_collected + 1}/{ALL_MODE_LIMIT})")
                        else:
                            if len(valid_ips_by_region[colo]) < sync_count:
                                valid_ips_by_region[colo].append(result)
                                print(f"[FOUND {colo}] {result['ip']} (Total {colo}: {len(valid_ips_by_region[colo])}/{sync_count})")
                total_collected = sum(len(ips) for ips in valid_ips_by_region.values())
                if is_scan_all and total_collected >= ALL_MODE_LIMIT:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                elif not is_scan_all and all(len(ips) >= sync_count for ips in valid_ips_by_region.values()):
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    print("\nScan completed. Summary:")
    total_found = 0
    all_best_ips = []
    for region, ips in valid_ips_by_region.items():
        print(f"- {region}: {len(ips)} valid IPs found")
        if not ips:
            print(f"  Warning: No IPs found for {region}")
            continue
        total_found += len(ips)
        ips.sort(key=lambda x: x["latency"])
        limit = ALL_MODE_LIMIT if is_scan_all else sync_count
        best_ips = ips[:limit]
        all_best_ips.extend(best_ips)
        print(f"\n--- Top {len(best_ips)} IPs Selected for {region} ---")
        for ip in best_ips:
            print(f"IP: {ip['ip']:<15} | Latency: {ip['latency']:>3}ms | Colo: {ip['colo']}")
        if can_sync:
            target_domain = f"{region.lower()}.{base_domain}"
            print(f"\nStarting Cloudflare DNS Sync for {target_domain}...")
            sync_to_cloudflare(api_token, zone_id, target_domain, best_ips, cf_email)
        else:
            print(f"\nSkipping DNS Sync for {region}")

    if can_sync and all_best_ips:
        if SYNC_MAIN_DOMAIN.strip().upper() == "YES":
            all_best_ips.sort(key=lambda x: x["latency"])
            print(f"\n[Global Sync] Syncing to MAIN DOMAIN: {base_domain}")
            sync_to_cloudflare(api_token, zone_id, base_domain, all_best_ips, cf_email)

    if total_found == 0:
        print("No valid IPs found. 原因90%是 CHECK_API_URL 用了 connect() 版的 velvet，被 CF 拦了。换成 nyc.mn 或 yp.myoo.ccwu.cc 这种 fetch 版的接口就能出。")
        exit(1)

    if all_best_ips:
        save_ips_to_file(all_best_ips)

if __name__ == "__main__":
    main()
