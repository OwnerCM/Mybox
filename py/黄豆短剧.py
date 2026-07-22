# -*- coding: utf-8 -*-
"""
黄豆短剧新版爬虫
站点: https://xqjzvcvt.top

无第三方依赖：仅使用 Python 标准库
"""

import gzip
import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.request
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from base.spider import Spider as BaseSpider
except ImportError:
    class BaseSpider:
        pass


# ==================== 纯 Python AES-256-CBC ====================

S_BOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
)

R_CON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def _bytes2matrix(text):
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def _matrix2bytes(matrix):
    return bytes(sum(matrix, []))


def _xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ _xtime(a[0] ^ a[1])
    a[1] ^= t ^ _xtime(a[1] ^ a[2])
    a[2] ^= t ^ _xtime(a[2] ^ a[3])
    a[3] ^= t ^ _xtime(a[3] ^ u)


def _sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX[s[i][j]]


def _inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = INV_S_BOX[s[i][j]]


def _shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def _inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def _mix_columns(s):
    for i in range(4):
        _mix_single_column(s[i])


def _inv_mix_columns(s):
    for i in range(4):
        u = _xtime(_xtime(s[i][0] ^ s[i][2]))
        v = _xtime(_xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    _mix_columns(s)


def _add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def _expand_key(master_key):
    key_columns = _bytes2matrix(master_key)
    iteration_size = len(master_key) // 4
    n_rounds = {4: 10, 6: 12, 8: 14}[iteration_size]
    i = 1
    while len(key_columns) < (n_rounds + 1) * 4:
        word = list(key_columns[-1])
        if len(key_columns) % iteration_size == 0:
            word.append(word.pop(0))
            word = [S_BOX[b] for b in word]
            word[0] ^= R_CON[i]
            i += 1
        elif iteration_size == 8 and len(key_columns) % iteration_size == 4:
            word = [S_BOX[b] for b in word]
        word = [x ^ y for x, y in zip(word, key_columns[-iteration_size])]
        key_columns.append(word)
    return [key_columns[4 * i:4 * (i + 1)] for i in range(len(key_columns) // 4)]


class PureAES:
    def __init__(self, master_key):
        self.round_keys = _expand_key(master_key)
        self.n_rounds = len(self.round_keys) - 1

    def encrypt_block(self, plaintext):
        state = _bytes2matrix(plaintext)
        _add_round_key(state, self.round_keys[0])
        for i in range(1, self.n_rounds):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self.round_keys[i])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self.round_keys[-1])
        return _matrix2bytes(state)

    def decrypt_block(self, ciphertext):
        state = _bytes2matrix(ciphertext)
        _add_round_key(state, self.round_keys[-1])
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        for i in range(self.n_rounds - 1, 0, -1):
            _add_round_key(state, self.round_keys[i])
            _inv_mix_columns(state)
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
        _add_round_key(state, self.round_keys[0])
        return _matrix2bytes(state)


def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    n = data[-1]
    if n < 1 or n > 16:
        raise ValueError("AES padding error")
    return data[:-n]


def _aes_cbc_encrypt(key, iv, data):
    aes = PureAES(key)
    data = _pkcs7_pad(data)
    out = []
    prev = iv
    for i in range(0, len(data), 16):
        block = _xor_bytes(data[i:i + 16], prev)
        enc = aes.encrypt_block(block)
        out.append(enc)
        prev = enc
    return b"".join(out)


def _aes_cbc_decrypt(key, iv, data):
    aes = PureAES(key)
    out = []
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        dec = _xor_bytes(aes.decrypt_block(block), prev)
        out.append(dec)
        prev = block
    return _pkcs7_unpad(b"".join(out))


class Spider(BaseSpider):
    """黄豆短剧新版"""

    BASE_URL = "https://xqjzvcvt.top"
    API_BASE = BASE_URL + "/api"

    WEB_AES_KEY = b"7961beb44246e3012ce228d6b5ced05a"
    VERSION = "1.0.0"
    LINE_CODE = "china_4"
    HOME_PAGE_SIZE = 6
    CATEGORY_PAGE_SIZE = 12
    CATEGORY_THREADS = 4
    DEFAULT_NAV = [
        {"code": "yuandou", "name": "黄豆原创"},
        {"code": "aiman", "name": "AI漫剧"},
        {"code": "erciyuan", "name": "二次元"},
        {"code": "caibian", "name": "擦边短剧"},
        {"code": "zhenren", "name": "真人短剧"},
        {"code": "heiliao", "name": "黑料"},
    ]
    CATEGORY_MAP = {
        "yuandou": [
            {"source": "rp"},
        ],
        "aiman": [
            {"cat_id": "327401", "order": "new", "tag_id": "500003"},
            {"cat_id": "327401", "order": "new", "tag_id": "500001"},
            {"cat_id": "327401", "order": "new", "tag_id": "500002"},
        ],
        "erciyuan": [
            {"cat_id": "817201", "order": "new"},
            {"cat_id": "900010", "order": "new"},
            {"cat_id": "481301", "order": "new"},
            {"cat_id": "900002", "order": "new"},
            {"cat_id": "900004", "order": "new"},
            {"cat_id": "451201", "order": "new"},
        ],
        "caibian": [
            {"cat_id": "246505", "order": "hot"},
            {"cat_id": "246505", "order": "new"},
            {"cat_id": "246505"},
        ],
        "zhenren": [
            {"cat_id": "817202", "order": "new"},
            {"cat_id": "900006", "order": "new"},
            {"cat_id": "900008", "order": "new"},
            {"cat_id": "900007", "order": "new"},
        ],
        "heiliao": [
            {"keywords": "黑料"},
        ],
    }
    _GLOBAL_TOKEN = ""
    _GLOBAL_HOME_CACHE = None
    _GLOBAL_CATEGORY_CACHE = {}

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self):
        super().__init__()
        self.name = "黄豆短剧"
        self.headers = {
            "User-Agent": self.USER_AGENT,
            "Origin": self.BASE_URL,
            "Referer": self.BASE_URL + "/",
            "Accept": "*/*",
        }
        self.ssl_context = ssl._create_unverified_context()
        self.device_id = str(uuid.uuid4())
        self.session_id = uuid.uuid4().hex
        self.token = self.__class__._GLOBAL_TOKEN
        self._nav_cache = None
        self._home_cache = self.__class__._GLOBAL_HOME_CACHE

    def init(self, extend="{}"):
        if extend:
            try:
                cfg = json.loads(extend)
                base_url = cfg.get("base_url") or cfg.get("url")
                if base_url:
                    self.BASE_URL = base_url.rstrip("/")
                    self.API_BASE = self.BASE_URL + "/api"
                self.LINE_CODE = cfg.get("line_code", self.LINE_CODE)
            except Exception as e:
                print(e)
        # 不在 init 里登录，避免 TVBox 初始化阶段就卡住；真正取数据时再懒加载。
        return None

    def getName(self):
        return "黄豆短剧"

    def homeContent(self, filter):
        self._ensure_login()
        if self._home_cache is not None:
            return self._home_cache
        result = {
            "class": [],
            "filters": {},
            "list": [],
            "parse": 0,
            "jx": 0,
        }
        try:
            nav = self._nav_list()
            for item in nav:
                tid = str(item.get("code") or item.get("id") or "")
                name = item.get("name") or item.get("code") or ""
                if tid and name:
                    result["class"].append({"type_id": tid, "type_name": name})

            data = self._api("/drama/list", {
                "page": "1",
                "page_size": str(self.HOME_PAGE_SIZE),
            })
            for item in self._items(data):
                result["list"].append(self._parse_vod(item))
        except Exception as e:
            print(e)
        self._home_cache = result
        self.__class__._GLOBAL_HOME_CACHE = result
        return result

    def categoryContent(self, tid, pg, filter, extend):
        self._ensure_login()
        cache_key = f"{tid}_{pg}_{json.dumps(extend or {}, ensure_ascii=False, sort_keys=True)}"
        if cache_key in self.__class__._GLOBAL_CATEGORY_CACHE:
            return self.__class__._GLOBAL_CATEGORY_CACHE[cache_key]
        result = {
            "page": int(pg),
            "pagecount": 999,
            "limit": 24,
            "total": 99999,
            "list": [],
            "parse": 0,
            "jx": 0,
        }
        try:
            items = []
            if tid and tid not in ("all", "0", "recommend"):
                filters = self.CATEGORY_MAP.get(str(tid), [])
                if filters:
                    items = self._load_category_filters(filters, pg)

                # 如果固定参数失效，动态从 navFilter 取第一个可用 filter。
                if not items:
                    data = self._api("/drama/navFilter", {"code": str(tid)})
                    dynamic_filters = []
                    for f in self._items(data):
                        if not isinstance(f, dict):
                            continue
                        flt = f.get("filter") or {}
                        if not flt:
                            continue
                        dynamic_filters.append(flt)
                    if dynamic_filters:
                        items = self._load_category_filters(dynamic_filters, pg)

            if not items and (not tid or tid in ("all", "0", "recommend")):
                body = {
                    "page": str(pg),
                    "page_size": str(self.CATEGORY_PAGE_SIZE),
                }
                if isinstance(extend, dict):
                    for key in ("order", "cat_id", "tag_id", "source", "canvas", "keywords", "update_status"):
                        val = extend.get(key)
                        if val:
                            body[key] = str(val)
                data = self._api("/drama/list", body)
                items = self._items(data)

            for item in items:
                result["list"].append(self._parse_vod(item))
            # TVBox 上滑会继续请求 pg+1；只要本页有数据，就不要过早结束分页。
            result["pagecount"] = 999 if items else int(pg)
            result["total"] = 999999 if items else 0
        except Exception as e:
            print(e)
        self.__class__._GLOBAL_CATEGORY_CACHE[cache_key] = result
        return result

    def _load_category_filters(self, filters, pg):
        """并发加载分类下多个子栏目，合并去重。"""
        def load_one(flt):
            body = {
                "page": str(pg),
                "page_size": str(self.CATEGORY_PAGE_SIZE),
            }
            for k, v in (flt or {}).items():
                if v not in (None, ""):
                    body[k] = str(v)
            data = self._api("/drama/list", body)
            return self._items(data)

        if len(filters) <= 1:
            try:
                return load_one(filters[0]) if filters else []
            except Exception:
                return []

        merged = []
        seen = set()
        workers = min(self.CATEGORY_THREADS, len(filters))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(load_one, flt) for flt in filters]
            for fu in as_completed(futures):
                try:
                    lst = fu.result()
                except Exception:
                    continue
                for item in lst:
                    if not isinstance(item, dict):
                        continue
                    vid = str(item.get("id") or item.get("drama_id") or item.get("name") or "")
                    if not vid or vid in seen:
                        continue
                    seen.add(vid)
                    merged.append(item)
        return merged

    def detailContent(self, ids):
        self._ensure_login()
        result = {"list": [], "parse": 0, "jx": 0}
        try:
            vid = str(ids[0])
            data = self._api("/drama/detail", {"id": vid})
            if not isinstance(data, dict):
                return result

            episodes = data.get("episodes") or []
            play_parts = []
            hls_id = str(data.get("drama_id") or "")
            if not hls_id:
                source = str(data.get("source") or "rp")
                hls_id = f"{source}_{vid}" if source and "_" not in vid else vid
            for ep in episodes:
                seq = str(ep.get("seq") or ep.get("index") or len(play_parts) + 1)
                ep_name = ep.get("name") or ep.get("title") or f"第{seq}集"
                # VIP 只是前端限制，真实 HLS 地址可直接按 drama_id/集数 拼出来。
                play_parts.append(f"{ep_name}${hls_id}@@{seq}")

            cover = self._cover(data)
            update_label = data.get("update_label") or ""
            episode_count = data.get("episode_count") or ""
            click = data.get("click") or data.get("hot_rate") or ""

            vod = {
                "vod_id": vid,
                "vod_name": data.get("name") or data.get("title") or "",
                "vod_pic": cover,
                "type_name": data.get("category") or "",
                "vod_year": "",
                "vod_area": "",
                "vod_remarks": update_label or (f"全{episode_count}集" if episode_count else ""),
                "vod_actor": "",
                "vod_director": "",
                "vod_content": data.get("description") or data.get("intro") or data.get("name") or "",
                "vod_play_from": "黄豆短剧",
                "vod_play_url": "#".join(play_parts),
            }
            if click:
                vod["vod_remarks"] = (vod["vod_remarks"] + f" · {click}热度").strip(" ·")
            result["list"].append(vod)
        except Exception as e:
            print(e)
        return result

    def searchContent(self, key, quick, pg="1"):
        self._ensure_login()
        result = {
            "page": int(pg),
            "pagecount": 999,
            "limit": 20,
            "total": 99999,
            "list": [],
            "parse": 0,
            "jx": 0,
        }
        try:
            data = self._api("/drama/list", {
                "page": str(pg),
                "page_size": "20",
                "keywords": key,
            })
            items = self._items(data)
            for item in items:
                result["list"].append(self._parse_vod(item))
            result["pagecount"] = int(pg) + 1 if len(items) >= 20 else int(pg)
        except Exception as e:
            print(e)
        return result

    def playerContent(self, flag, id, vipFlags):
        self._ensure_login()
        result = {
            "parse": 0,
            "playUrl": "",
            "url": "",
            "jx": 0,
            "header": {
                "User-Agent": self.USER_AGENT,
                "Referer": "http://www.qq.com",
            },
        }
        try:
            play_id = urllib.parse.unquote(str(id or "")).strip()
            if play_id.startswith("http://") or play_id.startswith("https://"):
                result["url"] = play_id
                return result

            if "@@" in play_id:
                parts = play_id.split("@@", 1)
                hls_id, seq = parts[0], parts[1] if len(parts) > 1 else "1"
            else:
                hls_id, seq = play_id, "1"

            if not hls_id.startswith(("rp_", "yd_", "ai_", "mv_")) and "_" not in hls_id:
                hls_id = "rp_" + hls_id

            result["url"] = f"{self.BASE_URL}/api/drama/hls/{hls_id}/{seq}/play.m3u8?line=free"
        except Exception as e:
            print(e)
        return result

    def localProxy(self, param):
        return [404, "text/plain", b""]

    # ==================== 新站协议 ====================

    def _ensure_crypto(self):
        return True

    def _ensure_login(self):
        if not self.token:
            self._login()

    def _login(self):
        try:
            data = self._api("/login/device", {
                "line_code": self.LINE_CODE,
                "channel_code": "",
                "share_code": "",
                "clipboard_text": "",
                "device_info": {
                    "browserName": "Chrome",
                    "language": "zh-CN",
                    "userAgent": self.USER_AGENT,
                    "platform": "Win32",
                },
            }, need_token=False)
            if isinstance(data, dict):
                self.token = data.get("token") or ""
                if self.token:
                    self.__class__._GLOBAL_TOKEN = self.token
        except Exception as e:
            print(f"login error: {e}")

    def _api(self, path, data=None, need_token=True):
        self._ensure_crypto()
        url = self.API_BASE + path
        request_id = str(uuid.uuid4())
        ts = int(time.time())
        no_proto_url = url.replace("https://", "").replace("http://", "")

        sign_src = f"Dart|{self.session_id}|{request_id}|{ts}|{no_proto_url}"
        sign = hashlib.md5(sign_src.encode("utf-8")).hexdigest() + f"-{ts}"

        headers = {
            "version": self.VERSION,
            "deviceType": "web",
            "time": str(ts),
            "sign": sign,
            "requestId": request_id,
            "sessionId": self.session_id,
            "deviceBrand": "",
            "deviceModel": "",
            "systemName": "",
            "systemVersion": "",
            "content-type": "application/x-www-form-urlencoded",
        }

        payload = {
            "token": self.token if need_token else "",
            "deviceId": self.device_id,
            "data": data,
        }

        key = self._aes_key(request_id)
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        raw = gzip.compress(raw)
        iv = os.urandom(16)
        body = iv + _aes_cbc_encrypt(key, iv, raw)

        content = self._post(url, headers, body)
        if content.startswith(b"{"):
            obj = json.loads(content.decode("utf-8"))
        else:
            iv2 = content[:16]
            enc = content[16:]
            dec = _aes_cbc_decrypt(key, iv2, enc)
            obj = json.loads(gzip.decompress(dec).decode("utf-8"))

        if obj.get("status") == "y":
            return obj.get("data")

        code = obj.get("errorCode")
        if code in (2002, "2002") and need_token:
            self.token = ""
            self._login()
            if self.token:
                return self._api(path, data, need_token=True)
        raise RuntimeError(obj.get("error") or f"接口错误: {obj}")

    def _aes_key(self, request_id):
        msg = bytes.fromhex(request_id.replace("-", ""))
        return hmac.new(self.WEB_AES_KEY, msg, hashlib.sha256).digest()

    def _post(self, url, headers, data):
        req_headers = dict(self.headers)
        req_headers.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=20, context=self.ssl_context) as resp:
            return resp.read()

    # ==================== 数据解析 ====================

    def _nav_list(self):
        if self._nav_cache is not None:
            return self._nav_cache
        # 分类在新 JS 里是固定的，首页不再请求 /drama/navList，少一次加密接口会快很多。
        self._nav_cache = list(self.DEFAULT_NAV)
        return self._nav_cache

    def _items(self, data):
        if isinstance(data, dict):
            lst = data.get("list") or data.get("items") or []
            return lst if isinstance(lst, list) else []
        if isinstance(data, list):
            return data
        return []

    def _cover(self, item):
        if not isinstance(item, dict):
            return ""
        return (
            item.get("img_x")
            or item.get("img_y")
            or item.get("img")
            or item.get("cover")
            or item.get("coverImg")
            or ""
        )

    def _parse_vod(self, item):
        vid = str(item.get("id") or item.get("drama_id") or "")
        episode_count = item.get("episode_count") or ""
        update_label = item.get("update_label") or item.get("corner") or ""
        remarks = update_label
        if not remarks and episode_count:
            remarks = f"全{episode_count}集"
        return {
            "vod_id": vid,
            "vod_name": item.get("name") or item.get("title") or "",
            "vod_pic": self._cover(item),
            "vod_remarks": remarks,
        }


if __name__ == "__main__":
    s = Spider()
    s.init()

    print("=== 首页 ===")
    home = s.homeContent(True)
    print("分类:", home["class"])
    print("推荐:", len(home["list"]))
    for v in home["list"][:5]:
        print(v)

    print("\n=== 搜索 重生 ===")
    so = s.searchContent("重生", False, "1")
    print("结果:", len(so["list"]))
    for v in so["list"][:5]:
        print(v)

    if so["list"]:
        vid = so["list"][0]["vod_id"]
        print("\n=== 详情 ===", vid)
        de = s.detailContent([vid])
        print(json.dumps(de, ensure_ascii=False)[:1000])
