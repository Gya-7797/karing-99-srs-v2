# Karing 99 个独立 SRS 规则（网页上传版）

此项目从原 Mihomo/Clash 配置中的 99 个 `rule-providers` 映射而来，不包含机场订阅、节点、策略组或订阅令牌。

运行 GitHub Actions 后会自动生成：

- `rules/`：99 个独立 `.srs` 文件；
- `source-json/`：对应的 sing-box 源 JSON；
- `KARING_URLS.md`：可粘贴到 Karing 的 Raw URL；
- `build-report.json`：构建详情和错误诊断。

## 重要：网页上传时的工作流文件

压缩包里的 `build-rules.yml` 暂时位于仓库根目录，目的是避免浏览器拒绝上传隐藏目录 `.github`。

全部文件上传后，请在 GitHub 中把它重命名为：

```text
.github/workflows/build-rules.yml
```

完成重命名后，GitHub Actions 会自动开始构建。

## 本次修订

转换器会在 YAML 解析前自动处理未加引号的通配符域名，例如：

```yaml
- *.163yun.com
```

并带有离线自测，工作流会先验证通配符转换和 SRS 编译器，再下载 99 项远程规则。
