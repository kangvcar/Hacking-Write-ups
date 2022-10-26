# 为 Hacking Write-ups 项目做贡献

## 欢迎贡献

Hacking Write-ups 项目欢迎并依赖于开源社区中开发人员和用户的贡献。可以通过多种方式做出贡献，例如：

- 通过拉取请求进行代码补丁
- 文档改进
- 错误报告和补丁审查


## 行为准则

在 Hacking Write-ups 项目的代码库、问题跟踪器、聊天室和邮件列表中进行交互的每个人都应遵循 [PyPA 行为准则](https://www.pypa.io/en/latest/code-of-conduct/)。


## 项目结构

    mkdocs.yml          # 项目配置文件
    requirements.txt    # 项目依赖
    docs/
        index.md        # 项目主页
        ...             # Other markdown pages, images and other files.
        cves/
            2022/
                images/
                    CVE-2022-XXXX-1.png   # CVE-2022-XXXX 的图片
                CVE-2022-XXXX.md          # CVE-2022-XXXX write-up
        vulnhub/
            images/
                Jarbas-1-1.png   # Jarbas-1 的图片
            Jarbas-1.md          # vulnhub Jarbas-1 write-up
        hackthebox/
            ...

## 添加文章的步骤

1. 在 `docs/cves/CVE-2022` 目录下创建一个新的 MD 文件，例如 `docs/cves/CVE-2022/CVE-2022-25411.md`。
2. 在新建 MD 文件的同级目录下的 `images` 文件夹中存放文章图片，例如 `docs/cves/CVE-2022/images/CVE-2022-25411-1.png`。
3. 在 `docs/cves/CVE-2022/CVE-2022-25411.md` 文件中添加文章内容。

    ```markdown
    # CVE-2022-25411
    
    ## 漏洞描述
    
    ## 影响范围
    
    ## 漏洞分析
    
    ## 漏洞利用
    
    ## 参考链接
    ```

4. 在 `docs/cves/CVE-2022/CVE-2022-25411.md` 文件中添加图片引用，例如 `![](images/CVE-2022-25411-1.png){ width=30% }`。
5. 在 `mkdocs.yml` 文件中添加文章的导航设置，例如：

    ```yaml hl_lines="11"
    nav:
     - Home:
       - 简介: index.md
       - 贡献指南: contribute.md
       - 讨论交流: discussion.md
       - Changelog: changelog.md
       - License: license.md
     - CVEs:
       - cves/index.md
       - CVE-2022:
         - cves/CVE-2022/CVE-2022-25411.md
         - cves/CVE-2022/CVE-2022-25488.md
     - VulnHub:
       - vulnhub/index.md
       - vulnhub/Jarbas-1.md
     - HackTheBox:
       - hackthebox/index.html
    ```

6. 更多支持的Markdown 语法请参考 [MkDocs Markdown Reference](https://squidfunk.github.io/mkdocs-material/reference/)。

## 如何贡献

1. Fork [本项目](https://github.com/kangvcar/Hacking-Write-ups)，然后克隆到本地，例如 `git clone https://github.com/kangvcar/Hacking-Write-ups.git` 。
2. 添加文章，参考上面的[添加文章的步骤](#_4)。
3. 提交您的更改，例如 `git commit -am 'Add article title'` 。
4. 将您的分支推送到 GitHub，例如 `git push` 。
5. 然后创建一个Pull Request。
6. 等待审核，如果有问题，我们会在评论中回复您。
7. 如果没有问题，我们会合并您的代码。
8. 感谢您的贡献！

## MKDocs 命令

* `mkdocs new [dir-name]` - Create a new project.
* `mkdocs serve` - Start the live-reloading docs server.
* `mkdocs build` - Build the documentation site.
* `mkdocs -h` - Print help message and exit.