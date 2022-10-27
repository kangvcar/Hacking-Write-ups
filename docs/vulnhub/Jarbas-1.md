# Jarbas 1

## Infomation

**Jarbas 1** is a vulnerable machine created by [VulnHub](https://www.vulnhub.com/entry/jarbas-1,232/). 

- [合天网安 VulnHub渗透测试实战靶场Jarbas 1](https://www.hetianlab.com/expc.do?ce=b06710c4-ecd4-41ea-ab7b-c3602df06219)

## 思路

### 0x01

善用 nmap

- `nmap -sP 10.1.1.1/24` 找到主机
- `nmap -A 10.1.1.91` 找到开放端口和服务

如果有网站就直接访问看看有没有可疑的地方，或者用目录扫描工具扫一下。

- `dirb http://10.1.1.91/ -X .html` 扫一下html结尾的页面

找到可用的信息之后，就可以开始利用了。

尝试用找到的登录信息登录一些开放的服务，比如ssh，ftp，mysql，网站后台等等。

### 0x02

网站也是一个很好的入口，如果有漏洞的话，可以直接拿到shell。

- 看看网站使用了什么框架，然后搜索一下漏洞
- 如果是wordpress，可以直接用`wpscan`扫一下
- 如果是php，可以用`phpggc`生成一下payload
- 如果是java，可以用`ysoserial`生成一下payload

msfconsole 也是一个很好的工具，可以直接用来找漏洞，或者生成 payload。

这个镜像就是使用 msf 来反弹shell的。

### 0x03

获得目标机器的权限之后，就可以开始提权了。

在主机中发现有个定时任务，每隔五分钟执行一次，执行权限是root。

这里就可以利用这个执行文件来提权了，有如下三种思路：

#### 第一种

1. 在定时任务中写入 `chmod u+s /usr/bin/find` 
2. 这样我们就给 find 命令加上了 setuid 权限，意思就是说，当普通用户执行 find 命令的时候拥有和 root 用户一样的权限。

???+ tip "利用原理"

    利用程序自身的命令执行参数，如：

    1. find 命令的`-exec`功能
    2. vim 命令的`:shell`功能
    3. 老版 nmap 交互界面的!sh功能

#### 第二种

1. 在定时任务中写入 `chmod u+s /usr/bin/cp`
2. cat查看目标机的 /etc/passwd 内容，复制下来在本地制作一份同样的并加入新用户（新用户uid为0，gid为0），然后上传到目标机
3. 然后利用cp命令把文字复制到 /etc/passwd 覆盖掉原文件，这样就可以直接用新用户登录了，就得到了一个root shell

#### 第三种

1. 用`msfvenom`生成一个反弹shell
2. 然后将这个反弹shell指令写入到目标机的定时任务中
3. 等待定时任务执行，就可以得到一个root shell

## 总结

- 利用了 msf 的 `exploit/multi/http/jenkins_script_console`
- 如果目标机器部署了网站，这是一个很好的入口
- 通过 /etc/passwd 文件创建特权用户
- 通过定时任务执行命令提权
- 巧用 find 命令的 `-exec` 参数来执行命令
- 目录扫描工具 dirb
