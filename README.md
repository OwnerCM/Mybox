# mybox

个人订阅源聚合工具，定时从多个源下载配置，合并去重后生成统一文件。通过 GitHub Actions 每日自动更新。

## 订阅地址

```
https://raw.githubusercontent.com/你的用户名/mybox/main/tvbox.json
```

## 更新频率

每天北京时间 **06:00** 和 **18:00** 自动更新，也支持手动触发。

## 项目结构

```
├── config.json              # 源配置（含注释说明）
├── api.json                 # 自定义接口（采集站、Python爬虫等）
├── merge.py                 # 合并脚本
├── requirements.txt         # Python 依赖
├── tvbox.json               # 合并输出（自动生成）
├── py/                      # Python 爬虫脚本目录
└── .github/workflows/
    └── update.yml           # 定时任务
```

## 本地运行

```bash
pip install -r requirements.txt
python merge.py
```

## 数据源

| 名称 | 格式 | 说明 |
| --- | --- | --- |
| 嗷呜 | 图片隐写+Base64 | WEBP 图片尾部追加 Base64 编码的 JSON |
| 潇洒 | AES-CBC 加密 | `$# + key + #$ + 密文hex + iv` |
| 王二小放牛娃 | 明文 JSON | 需要 okhttp UA |
| 自定义 | 本地文件 `api.json` | CMS 采集站 + Python 爬虫，跳过去重 |

## 合并流程

```
下载/解密 → 合并 → 过滤 → 去重 → 分类排序 → 插入更新日期 → 输出
```

## 规则说明

### 过滤（先于去重执行）

- **全局关键词过滤**：站点名包含关键词的直接移除
- **按源过滤**：指定源的特定关键词（如潇洒/王二小的 4K 类）
- **按源过滤例外**：即使命中按源过滤，包含例外关键词的保留（如王二小的"观影"）

### 去重（两级）

1. 按 `key` 精确去重
2. 按 `name` 跨源模糊去重（去掉 emoji/符号后比较核心名称，同源内多线路保留）

### 特殊规则

- `dedup_aliases`：同义词归类（如"豆瓣推荐"和"豆瓣首页"视为同一站点）
- `dedup_prefer_source`：指定站点优先保留哪个源（如"观影"优先王二小）
- `skip_dedup`：自定义源跳过所有去重逻辑

### 分类排序

合并后按以下顺序排列（未匹配的放末尾）：

置顶 → 采集 → 4K网盘 → 秒播 → 2K → 影视 → 动漫 → 短剧 → 墙外 → 直播

### spider/jar 处理

- 全局 spider 取第一个源（嗷呜）的
- 其他源的站点自动注入各自的 `jar` 字段

## 添加新源

编辑 `config.json` 的 `sources` 数组，支持四种格式：

| 配置 | 说明 |
| --- | --- |
| 默认 | 明文 JSON |
| `"encrypted": true` | AES-CBC 加密 |
| `"format": "image_base64"` | 图片隐写 + Base64 |
| `"url": "file://xxx.json"` | 本地文件 |

## 添加自定义接口

编辑 `api.json`，支持 CMS 采集站（type=1）和 Python 爬虫（type=3）。
