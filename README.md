# mybox

个人订阅源聚合工具，定时从多个源下载配置，合并去重后生成统一文件。通过 GitHub Actions 每日自动更新。

## 订阅地址

```
https://raw.githubusercontent.com/你的用户名/mybox/main/tvbox.json
```

## 更新频率

每天北京时间 06:00 和 18:00 自动更新，支持手动触发。

## 本地运行

```bash
pip install -r requirements.txt
python merge.py
```

## 合并流程

```
下载/解密 → 合并 → 过滤 → 去重 → 分类排序 → 插入更新日期 → 输出
```

## 规则说明

- **过滤**：全局关键词过滤 + 按源专属过滤，先于去重执行
- **去重**：key 精确去重 → name 跨源模糊去重（同源多线路保留）
- **同义词归类**：不同名但实质相同的站点视为一组
- **分类排序**：按配置的分类顺序排列，未匹配放末尾
- **spider/jar**：全局 spider 取首个源，其他源站点自动注入 jar
- **自定义接口**：`api.json` 中的站点跳过去重直接追加

## 支持的源格式

- 明文 JSON
- AES-CBC 加密
- 图片隐写 + Base64
- 本地文件（`file://`）

## 配置文件

- `config.json` — 源地址、过滤规则、去重规则、排序规则
- `api.json` — 自定义接口（CMS 采集站、Python 爬虫等）
