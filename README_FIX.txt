Karing 自建 banad 规则 RE2 兼容修复补丁

把下面三个文件覆盖到 GitHub 仓库相同路径：
1. scripts/build_rules.py
2. scripts/self_test.py
3. providers.json

修复内容：
- 不再使用 Python fnmatch.translate() 生成通配符正则。
- 改成 Go/RE2 可识别的简单正则，避免出现 (?>...) 原子组。
- 输出文件改名为 banad_domain_re2.srs，绕开 jsDelivr 对旧文件的分支缓存。

提交后 GitHub Actions 会自动重建全部 99 个 SRS。
成功后 Karing 使用：
https://fastly.jsdelivr.net/gh/Gya-7797/karing-99-srs-v2@main/rules/banad_domain_re2.srs
