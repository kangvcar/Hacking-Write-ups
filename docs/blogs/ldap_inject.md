# LDAP 注入漏洞

## LDAP 语法

1. `=`（等于）
	查找‘Name’属性为‘John’的所有对象，可以使用：(Name=John)

	注：圆括号用于强调LDAP语句的开始和结束。

2. `&`（逻辑与）
	如果具有多个条件，并且希望所有条件都满足，则使用该语法。如使用以下语句查询居住在Hong Kong，且名为John的所有人员：(&(Name=John)(live=Hong Kong))

	操作符&表明，只有每个参数都为真，才会将此筛选条件应用到要查询的对象。

3. `|`（逻辑或）
	结合过滤器，相应系列中必须至少有一个条件为真。

4. `！`（逻辑非）
	用来排除具有特定属性的对象，如查找所有‘name’不为‘John’的人员：(!Name=John)

5. `*`（通配符）
	表示值可以等于任何内容，如查找具有职务头衔的所有人员：(title=*)；查找所有‘Name’以‘Jo’开头的人员：(Name=Jo*)

6. `()`（括号）
	分离过滤器，用来让其他逻辑运算符发挥作用。

## LDAP 常见注入方式

### 漏洞成因

没有对用户输入的合法性进行验证，直接将数据发送给服务器进行查询，导致攻击者可以注入恶意代码。

### 思路

利用用户引入的参数生成 LDAP 查询

### AND注入

当后端的代码为：`(&(parameter1=value1)(parameter2=value2))`

这里 value1 和 value2 都会被查询，且是用户可控的，如果过滤不完善，就会存在 LDAP 注入。

比如一个用户登录的场景，用户输入 username 和 password ，应用会构造一个过滤器并发送给 LDAP 服务器进行查询。如 `(&(username=uname)(password=pwd))`

当用户输入一个有效的用户名，如 admin，那么就有可能在 username 字段后面进行注入，从而在不知道密码的情况下进行登录。

Payload：`admin)(&))`

Result：`(&(username=admin)(&))(password=123))`

**LDAP 服务器只会处理第一个过滤器，而第一个过滤器永远为真，因此绕过了登录框。**

### OR注入

当后端代码为：`(|(parameter1=value1)(parameter2=value2))`

假设一个资源管理器允许用户了解系统中可用的资源，如打印机、扫描器、存储系统等，用于展示可用资源的查询为 `(|(type=Rsc1) (type=Rsc2))`

Rsc1 和 Rsc2 表示系统中不同种类的资源，如 Rsc1=printer、Rsc2=scanner，用于列出系统中所有可用的打印机和扫描器。

Payload：`Rsc1=printer)(uid=*)`

Result：`(|(type=printer)(uid=*)) (type=scanner))`

**LDAP服务器会响应所有的打印机和用户对象。**

### AND盲注

假设一个Web应用想从一个 LDAP 目录列出所有可用的 Epson 打印机，不会返回错误信息，应用发送如下的过滤器：`(&(objectclass=printer)(type=Epson*))`

使用这个查询，如果有可用的 Epson 打印机，其图标就会显示给客户端。如果攻击者进行 LDAP 盲注攻击，payload为：`*)(objectClass=*))(&(objectclass=void`

Web应用会构造如下查询：

`(&(objectclass=*)(objectClass=*))(&(objectClass=void)(type=Epson*))`

仅对第一个过滤器进行处理：`(&(objectclass=*)(objectClass=*))`

结果是打印机的图标一定会显示出来，因为该查询永远有结果，过滤器objectClass=*总是返回一个对象。当图标被显示时响应为真，否则为假。

例如构造如下的注入：

`(&(objectClass=*)(objectClass=users))(&(objectClass=foo)(type=Epson*))`

`(&(objectClass=*)(objectClass=resources))(&(objectClass=foo)(type=Epson*))`

这种代码注入的设置允许攻击者推测可能存在于 LDAP 目录服务中不同对象类的值，当响应 Web 页面至少包含一个打印机图标时，对象类的值就是存在的。另一方面如果对象类的值不存在或没有对它进行访问，就不会有图标出现。

### OR盲注

这种情况下用于推测想要信息的逻辑是相反的，因为使用的是OR逻辑操作符。

例如 OR 环境的注入为：

`(|(objectClass=void)(objectClass=void))(&(objectClass=void)(type=Epson*))`

这个 LDAP 查询没有从 LDAP 目录服务获得任何对象，打印机的图标也不会显示给客户端即响应为 FALSE。如果在响应的 Web 页面中有任何图标，则响应为 TRUE。

攻击者可以注入下列 LDAP 过滤器来收集信息：

`(|(objectClass=void)(objectClass=users))(&(objectClass=void)(type=Epson*))`

`(|(objectClass=void)(objectClass=resources))(&(objectClass=void)(type=Epson*))`