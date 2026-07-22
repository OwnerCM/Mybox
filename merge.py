#!/usr/bin/env python3
"""
TVBox 接口聚合脚本
功能：从多个源下载 TVBox 配置（支持明文和加密），合并去重后输出为单一 JSON 文件
"""

import json
import os
import re
import sys
import time
import base64
import binascii
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta

import requests
from Crypto.Cipher import AES

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# 项目根目录
ROOT_DIR = Path(__file__).parent


def load_config() -> dict:
    """加载配置文件"""
    config_path = ROOT_DIR / "config.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def decrypt_tvbox(content: str) -> str:
    """
    解密 TVBox 加密配置
    格式：$# + key + #$ + 密文(hex) + iv(末尾13字符)
    算法：AES-128-CBC
    """
    content = content.strip()

    # 验证是否为加密格式
    if not content.startswith("2423"):
        raise ValueError("不是有效的 TVBox 加密格式（缺少 2423 开头标识）")

    # 将 hex 字符串转为 ASCII
    ascii_content = binascii.unhexlify(content).decode("utf-8", errors="replace")

    # 提取 key：$# 和 #$ 之间
    try:
        key_start = ascii_content.index("$#") + 2
        key_end = ascii_content.index("#$")
    except ValueError:
        raise ValueError("无法在解码内容中找到 $# 或 #$ 标记")

    key_raw = ascii_content[key_start:key_end]
    key = key_raw.ljust(16, "0")[:16]

    # 提取 iv：末尾 13 个字符
    iv_raw = ascii_content[-13:]
    iv = iv_raw.ljust(16, "0")[:16]

    # 提取密文 data：从 hex 中 "2324" 标记之后到末尾减 26 个字符
    marker_pos = content.index("2324") + 4
    data_hex = content[marker_pos: len(content) - 26]
    data_bytes = binascii.unhexlify(data_hex)

    # AES-CBC 解密
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    decrypted = cipher.decrypt(data_bytes)

    # 去除 PKCS7 padding
    pad_len = decrypted[-1]
    if 1 <= pad_len <= 16:
        decrypted = decrypted[:-pad_len]

    return decrypted.decode("utf-8")


def download_source(url: str, config: dict, fmt: str = "json"):
    """下载单个接口源，支持重试"""
    req_config = config.get("request", {})
    timeout = req_config.get("timeout", 15)
    user_agent = req_config.get("user_agent", "okhttp/4.12.0")
    retries = req_config.get("retries", 2)

    headers = {"User-Agent": user_agent}

    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()
            if fmt == "image_base64":
                return resp.content  # 返回 bytes
            return resp.text
        except requests.RequestException as e:
            if attempt < retries:
                logger.warning(f"  下载失败（第 {attempt + 1} 次），重试中... 错误: {e}")
                time.sleep(2)
            else:
                logger.error(f"  下载失败（已重试 {retries} 次）: {e}")
                return None


def parse_source(raw_content, encrypted: bool, source_name: str, fmt: str = "json"):
    """
    解析接口源内容
    支持格式：
    - json: 明文 JSON
    - encrypted: AES 加密
    - image_base64: 图片隐写 + Base64（WEBP/PNG 图片后追加 Base64 数据）
    """
    try:
        if fmt == "image_base64":
            # 图片隐写格式：RIFF(WEBP) 头 + 图片数据 + ** + Base64(JSON)
            logger.info(f"  正在解析图片隐写格式 [{source_name}]...")
            if isinstance(raw_content, str):
                raw_bytes = raw_content.encode("latin-1")
            else:
                raw_bytes = raw_content

            # 找到 RIFF 声明的大小，跳过图片数据
            if raw_bytes[:4] == b"RIFF":
                riff_size = int.from_bytes(raw_bytes[4:8], "little")
                extra = raw_bytes[8 + riff_size:]
            elif raw_bytes[:8] == b"\x89PNG\r\n\x1a\n":
                # PNG 格式：找 IEND 标记后的数据
                iend_pos = raw_bytes.find(b"IEND")
                if iend_pos >= 0:
                    extra = raw_bytes[iend_pos + 8:]  # IEND + 4 bytes CRC
                else:
                    raise ValueError("PNG 格式但找不到 IEND 标记")
            else:
                raise ValueError("不是有效的图片隐写格式")

            extra_text = extra.decode("utf-8", errors="replace")

            # 找到 ** 分隔符
            marker_pos = extra_text.find("**")
            if marker_pos < 0:
                raise ValueError("图片数据后找不到 ** 分隔符")

            b64_data = extra_text[marker_pos + 2:]
            raw_content = base64.b64decode(b64_data).decode("utf-8")

        elif encrypted:
            logger.info(f"  正在解密 [{source_name}]...")
            raw_content = decrypt_tvbox(raw_content)

        data = json.loads(raw_content)
        return data
    except (ValueError, json.JSONDecodeError) as e:
        logger.error(f"  解析失败 [{source_name}]: {e}")
        return None


def extract_core_name(name: str) -> str:
    """
    提取站点名称的核心部分，用于模糊去重
    去掉 emoji、特殊符号、序号、分隔符等修饰字符
    """
    # 去掉常见 emoji 和装饰符号
    name = re.sub(r'[\U0001F300-\U0001F9FF\u2600-\u27BF\u2B50\u26A1]', '', name)
    # 去掉中文/英文特殊符号、分隔符
    name = re.sub(r'[•┃|【】\[\]()（）《》<>★☆♠♣♥♦\s]', '', name)
    # 去掉数字序号
    name = re.sub(r'[①②③④⑤⑥⑦⑧⑨⑩⓪❶❷❸❹❺❻❼❽❾❿]', '', name)
    # 去掉 emoji 残留（Variation Selectors 等）
    name = re.sub(r'[\uFE00-\uFE0F\u200D]', '', name)
    return name.strip()


def deduplicate_list(items: list, key_field: str, keep_first: bool = True) -> list:
    """按指定字段去重"""
    seen = {}
    result = []

    for item in items:
        k = item.get(key_field)
        if k is None:
            # 没有 key 字段的项目直接保留
            result.append(item)
            continue

        if k not in seen:
            seen[k] = True
            result.append(item)
        elif not keep_first:
            # 保留最后一个：替换
            for i, existing in enumerate(result):
                if existing.get(key_field) == k:
                    result[i] = item
                    break

    return result


def merge_configs(configs: list, merge_settings: dict, global_config: dict, source_names: list) -> dict:
    """
    合并多个 TVBox 配置
    策略：
    - spider: 使用第一个有效值（作为默认 spider）
    - sites: 合并所有，按 key 去重；为非默认 spider 的站点注入 jar 字段
    - lives: 合并所有，按 name 去重
    - parses: 合并所有，按 name 去重
    - doh/rules/ijk/ads: 合并所有
    """
    deduplicate = merge_settings.get("deduplicate_sites", True)
    dedup_field = merge_settings.get("deduplicate_by", "key")
    keep_first = merge_settings.get("keep_first", True)

    merged = {
        "spider": "",
        "wallpaper": "",
        "logo": "",
        "danmaku": "",
        "sites": [],
        "lives": [],
        "parses": [],
        "flags": [],
        "doh": [],
        "rules": [],
        "ijk": [],
        "ads": [],
        "proxy": []
    }

    # 收集所有源的 spider 地址
    all_spiders = []
    for config in configs:
        spider = config.get("spider", "")
        all_spiders.append(spider)

    # 第一个非空 spider 作为全局默认
    default_spider = ""
    for s in all_spiders:
        if s:
            default_spider = s
            break

    for idx, config in enumerate(configs):
        source_spider = config.get("spider", "")
        source_name = source_names[idx] if idx < len(source_names) else ""

        # spider：取第一个非空值
        if not merged["spider"] and source_spider:
            merged["spider"] = source_spider

        # 字符串字段：取第一个非空值
        for str_field in ["wallpaper", "logo", "danmaku"]:
            if not merged[str_field] and config.get(str_field):
                merged[str_field] = config[str_field]

        # sites：如果该源的 spider 与默认 spider 不同，给每个 site 注入 jar 字段
        sites = config.get("sites", [])
        if isinstance(sites, list):
            if source_spider and source_spider != default_spider:
                for site in sites:
                    # 如果站点本身没有指定 jar，且使用了 type 3（爬虫类型），注入源的 spider
                    if "jar" not in site and site.get("type") == 3:
                        site["jar"] = source_spider
                logger.info(f"  为来自该源的 {len(sites)} 个站点注入 jar 字段")
            # 为每个站点标记来源索引，用于跨源去重
            for site in sites:
                site["_source_idx"] = idx
                site["_source_name"] = source_name
            merged["sites"].extend(sites)

        # 其他列表字段：追加
        for field in ["lives", "parses", "doh", "rules", "ijk", "ads", "proxy"]:
            items = config.get(field, [])
            if isinstance(items, list):
                merged[field].extend(items)

        # flags 特殊处理（字符串数组，合并去重）
        flags = config.get("flags", [])
        if isinstance(flags, list):
            merged["flags"].extend(flags)

    # 去重
    if deduplicate:
        original_sites = len(merged["sites"])
        # 第一步：按 key 精确去重
        merged["sites"] = deduplicate_list(merged["sites"], dedup_field, keep_first)
        after_key_dedup = len(merged["sites"])

        # 第二步：按 name 模糊匹配跨源去重
        # 策略：
        # - 同一个源内的同名站点保留（作者有意配置的多线路）
        # - 跨源出现的同名站点只保留第一个源的（除非有优先源规则）
        # - dedup_skip_keywords 中的关键词跳过去重（各源都保留）
        # - dedup_prefer_source 指定某些站点优先使用哪个源
        fuzzy_deduped = []
        seen_core = {}  # dedup_key -> (source_idx, list_index)
        fuzzy_removed = 0

        # 加载同义词归类
        dedup_aliases = global_config.get("dedup_aliases", {})
        alias_map = {}
        for group_key, aliases in dedup_aliases.items():
            if group_key.startswith("_"):
                continue
            if isinstance(aliases, list):
                for alias in aliases:
                    alias_map[alias] = group_key

        # 加载跳过去重的关键词
        skip_keywords_conf = global_config.get("dedup_skip_keywords", {})
        if isinstance(skip_keywords_conf, list):
            skip_keywords = skip_keywords_conf
        elif isinstance(skip_keywords_conf, dict):
            skip_keywords = skip_keywords_conf.get("keywords", [])
        else:
            skip_keywords = []

        # 加载优先源规则：core关键词 -> 源名称
        prefer_source = global_config.get("dedup_prefer_source", {})
        prefer_source = {k: v for k, v in prefer_source.items() if not k.startswith("_")}

        for site in merged["sites"]:
            name = site.get("name", "")
            core = extract_core_name(name)
            source_idx = site.get("_source_idx", 0)
            source_name = site.get("_source_name", "")

            # 跳过去重：包含特定关键词的站点各源都保留
            if any(kw in name for kw in skip_keywords):
                fuzzy_deduped.append(site)
                continue

            # 只对有效核心名称进行模糊匹配（至少2个字符）
            if core and len(core) >= 2:
                dedup_key = alias_map.get(core, core)

                if dedup_key in seen_core:
                    first_source_idx, first_list_idx = seen_core[dedup_key]
                    if first_source_idx != source_idx:
                        # 跨源重复：检查是否有优先源规则
                        preferred = None
                        for pref_kw, pref_src in prefer_source.items():
                            if pref_kw in core:
                                preferred = pref_src
                                break

                        if preferred and preferred == source_name:
                            # 当前站点来自优先源，替换掉之前保留的
                            fuzzy_deduped[first_list_idx] = None  # 标记为替换
                            seen_core[dedup_key] = (source_idx, len(fuzzy_deduped))
                            fuzzy_deduped.append(site)
                            fuzzy_removed += 1  # 仍然算去重了一个
                        else:
                            # 去掉当前的
                            fuzzy_removed += 1
                        continue
                    # 同源内的同名保留
                else:
                    seen_core[dedup_key] = (source_idx, len(fuzzy_deduped))

            fuzzy_deduped.append(site)

        # 清理 None 标记和临时字段
        fuzzy_deduped = [s for s in fuzzy_deduped if s is not None]
        for site in fuzzy_deduped:
            site.pop("_source_idx", None)
            site.pop("_source_name", None)

        merged["sites"] = fuzzy_deduped
        logger.info(f"  sites 去重: {original_sites} -> {after_key_dedup}(key) -> {len(merged['sites'])}(跨源模糊), 跨源模糊去重移除 {fuzzy_removed} 个")

    # lives 按 name 去重
    if merged["lives"]:
        original_lives = len(merged["lives"])
        merged["lives"] = deduplicate_list(merged["lives"], "name", keep_first)
        logger.info(f"  lives 去重: {original_lives} -> {len(merged['lives'])}")

    # parses 按 name 去重
    if merged["parses"]:
        original_parses = len(merged["parses"])
        merged["parses"] = deduplicate_list(merged["parses"], "name", keep_first)
        logger.info(f"  parses 去重: {original_parses} -> {len(merged['parses'])}")

    # doh 按 name 去重
    if merged["doh"]:
        original_doh = len(merged["doh"])
        merged["doh"] = deduplicate_list(merged["doh"], "name", keep_first)
        logger.info(f"  doh 去重: {original_doh} -> {len(merged['doh'])}")

    # ijk 按 group 去重
    if merged["ijk"]:
        original_ijk = len(merged["ijk"])
        merged["ijk"] = deduplicate_list(merged["ijk"], "group", keep_first)
        logger.info(f"  ijk 去重: {original_ijk} -> {len(merged['ijk'])}")

    # rules 按 hosts 去重（将 hosts 列表转为排序后的字符串作为唯一标识）
    if merged["rules"]:
        original_rules = len(merged["rules"])
        seen_rules = set()
        deduped_rules = []
        for rule in merged["rules"]:
            hosts = rule.get("hosts", [])
            # 用 hosts 排序后的字符串作为唯一标识
            rule_key = "|".join(sorted(hosts)) if hosts else ""
            if rule_key and rule_key in seen_rules:
                continue
            if rule_key:
                seen_rules.add(rule_key)
            deduped_rules.append(rule)
        merged["rules"] = deduped_rules
        logger.info(f"  rules 去重: {original_rules} -> {len(merged['rules'])}")

    # ads 去重（字符串列表直接去重，保持顺序）
    if merged["ads"]:
        original_ads = len(merged["ads"])
        seen_ads = set()
        deduped_ads = []
        for ad in merged["ads"]:
            if ad not in seen_ads:
                seen_ads.add(ad)
                deduped_ads.append(ad)
        merged["ads"] = deduped_ads
        logger.info(f"  ads 去重: {original_ads} -> {len(merged['ads'])}")

    # flags 去重（字符串列表去重）
    if merged["flags"]:
        original_flags = len(merged["flags"])
        seen_flags = set()
        deduped_flags = []
        for f in merged["flags"]:
            if f not in seen_flags:
                seen_flags.add(f)
                deduped_flags.append(f)
        merged["flags"] = deduped_flags
        logger.info(f"  flags 去重: {original_flags} -> {len(merged['flags'])}")

    # 移除空字段
    merged = {k: v for k, v in merged.items() if v}

    return merged


def add_update_info(merged: dict, parsed_configs: list) -> dict:
    """
    使用合并成功后的当天日期作为更新标记
    格式：更新日期:YYYYMMDD
    """
    beijing_tz = timezone(timedelta(hours=8))
    today = datetime.now(beijing_tz).strftime("%Y%m%d")

    # 在 sites 开头插入更新日期
    update_site = {
        "key": "_update_info",
        "name": "更新日期:{}".format(today),
        "type": 3,
        "api": "csp_Config",
        "searchable": 0,
        "changeable": 0
    }

    if "sites" in merged:
        merged["sites"].insert(0, update_site)

    logger.info(f"  更新日期: {today}")
    return merged


def main():
    logger.info("=" * 50)
    logger.info("TVBox 接口聚合开始")
    logger.info("=" * 50)

    # 加载配置
    config = load_config()
    sources = config["sources"]
    output_path = ROOT_DIR / config["output"]
    merge_settings = config.get("merge", {})

    logger.info(f"共 {len(sources)} 个接口源")

    # 下载并解析所有源
    parsed_configs = []
    source_names_list = []
    success_count = 0

    for i, source in enumerate(sources, 1):
        name = source["name"]
        url = source["url"]
        encrypted = source.get("encrypted", False)
        fmt = source.get("format", "json")

        logger.info(f"[{i}/{len(sources)}] 正在处理: {name}")
        logger.info(f"  URL: {url}")

        # 下载
        raw_content = download_source(url, config, fmt)
        if raw_content is None:
            logger.warning(f"  跳过 [{name}]（下载失败）")
            continue

        # 解析
        parsed = parse_source(raw_content, encrypted, name, fmt)
        if parsed is None:
            logger.warning(f"  跳过 [{name}]（解析失败）")
            continue

        sites_count = len(parsed.get("sites", []))
        lives_count = len(parsed.get("lives", []))
        parses_count = len(parsed.get("parses", []))
        logger.info(f"  ✅ 成功: {sites_count} sites, {lives_count} lives, {parses_count} parses")

        parsed_configs.append(parsed)
        source_names_list.append(name)
        success_count += 1

    if not parsed_configs:
        logger.error("所有接口源均失败，终止合并")
        sys.exit(1)

    logger.info(f"\n成功获取 {success_count}/{len(sources)} 个源")

    # 合并
    logger.info("\n开始合并...")
    merged = merge_configs(parsed_configs, merge_settings, config, source_names_list)

    # 过滤不需要的站点
    filter_settings = config.get("filter", {})
    exclude_keywords = filter_settings.get("exclude_keywords", [])
    if exclude_keywords and "sites" in merged:
        before_filter = len(merged["sites"])
        merged["sites"] = [
            site for site in merged["sites"]
            if not any(kw in site.get("name", "") for kw in exclude_keywords)
        ]
        filtered_count = before_filter - len(merged["sites"])
        if filtered_count > 0:
            logger.info(f"  关键词过滤: 移除 {filtered_count} 个站点 (规则: {exclude_keywords})")

    # 添加更新时间
    merged = add_update_info(merged, parsed_configs)

    # 统计
    logger.info(f"\n合并结果:")
    logger.info(f"  sites: {len(merged.get('sites', []))}")
    logger.info(f"  lives: {len(merged.get('lives', []))}")
    logger.info(f"  parses: {len(merged.get('parses', []))}")

    # 输出
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)

    file_size = output_path.stat().st_size / 1024
    logger.info(f"\n输出文件: {output_path} ({file_size:.1f} KB)")
    logger.info("=" * 50)
    logger.info("TVBox 接口聚合完成")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()
