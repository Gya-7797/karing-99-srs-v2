# 上传顺序

1. 新建一个空的 Public GitHub 仓库，不勾选 README、.gitignore 或 License。
2. 解压本压缩包。
3. 打开解压后的 `karing-99-srs-v2` 文件夹，把里面的全部内容拖入 GitHub 的 Upload files 页面。
4. 提交说明填写 `Initial upload v2`，直接提交到 `main`。
5. 回到仓库首页，打开根目录的 `build-rules.yml`。
6. 点击铅笔编辑，把文件名改成 `.github/workflows/build-rules.yml`。
7. 提交说明填写 `Enable build workflow`，直接提交到 `main`。
8. 打开 Actions，等待新的工作流完成。成功时会出现绿色对勾，并生成 `rules/`。
