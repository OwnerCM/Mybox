# mybox

个人订阅源聚合工具，定时从多个源下载配置，合并去重后生成统一文件。通过 GitHub Actions 每日自动更新。

## 订阅地址

```
https://raw.githubusercontent.com/你的用户名/mybox/main/output/tvbox.json
```

## 更新频率

每天北京时间 **06:00** 和 **18:00** 自动更新，也支持手动触发。

## 项目结构

```
├── config.json          # 源配置（含注释说明）
├── merge.py             # 合并脚本
├── requirements.txt     # Python 依赖
├── output/
│   └── tvbox.json       # 合并输出（自动生成）
└── .github/workflows/
    └── update.yml       # 定时任务
```

## 本地运行

```bash
pip install -r requirements.txt
python merge.py
```

## 添加新源

编辑 `config.json` 的 `sources` 数组，支持三种格式：

| format | 说明 |
| --- | --- |
| （默认） | 明文 JSON |
| `encrypted: true` | AES-CBC 加密 |
| `"format": "image_base64"` | 图片隐写 + Base64 |

## 去重规则

1. 按 `key` 精确去重
2. 按 `name` 跨源模糊去重（同源内多线路保留）
3. `dedup_skip_keywords` 中的关键词跳过去重
4. `dedup_prefer_source` 指定优先保留哪个源
5. `dedup_aliases` 同义词归类
6. `filter.exclude_keywords` 关键词过滤
