#配置文件的格式如下 下面例子前面的#需要去掉,配置好密码文件后，需要修改变量ip_list_file的值:
#[WEB]
#192.168.56.102 root liu123
#[DB]
#192.168.56.101 root liu123
#192.168.56.102 root liu123

#
#注意:如果发行版中没有pexpect模块 需要安装pexpect模块
#警告:密码需要明文写进配置文件，可能不安全
#
import pexpect
import re
import sys


def format_ip_str(ip_str):
    # 检查字符串，符合IP地址序列的，则将该字符串处理为列表。否则，视该字符串为群组名，调用srv_list()查找IP列表文件是否符合该群组名的IP.
    # 最后返回IP地址列表.
    def check_ip(ip_addr):
        # 接收ip_addr变量，判断其是否为合法的IP地址，如果为合法则返回真，否则返回False
        ip_pattern = re.compile(r'^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$')
        ip_match = ip_pattern.match(ip_addr)
        if ip_match:
            result = True
        else:
            result = False
        return result

    def proc_srv_list(groupname):    
        # 接收参数服务器组名，处理ip_list_file配置文件，返回IP地址列表。
        # 格式类似：['[DB]', '172.16.7.17', '172.16.7.183', '172.16.7.184']
        # 其中第一个元素为组名        
        f = open(ip_list_file,'r')
        iplist = []
        flag = 0
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip()
            flag_pattern = re.compile(r'^\[(.*)\]$')
            flag_match = flag_pattern.match(line)
            if flag_match:
                if flag_match.group(1) == groupname:
                    flag = 1
                elif (flag == 1) and flag_match.group(1) != groupname:
                    break
            if flag == 1:
                iplist.append(line)
        f.close()
        if len(iplist) != 0:
            del iplist[0]
        return iplist

    list = ip_str.split(',')
    logInfoList = []
    ip_string = check_ip(list[0])
    if ip_string:
        for element in list:
            flag = check_ip(element)
            if not flag:
                break
        if flag:
            for element in list:
                f = open(ip_list_file,'r')
                while True:
                    line = f.readline()
                    if not line:break
                    line = line.strip()
                    line_list = line.split(' ')
                    if line_list[0] == element:
                        logInfoList.append(line)
                        break                              #匹配到第一行即中断
                f.close()
    else:
        logInfoList = proc_srv_list(ip_str)
    return logInfoList


def print_Highlighted_Red(str):
    print '\033[1;44m %s \033[1;m' %str


class Batexec:
    def __init__(self,ip,user,passwd):
        self.IP = ip
        self.USER = user
        self.PASSWD = passwd

    def cmd(self,command):
        child = pexpect.spawn('ssh  %s@%s' %(self.USER,self.IP))
        print_Highlighted_Red(self.IP)
        try:
            i = child.expect(['assword: ', 'continue connecting (yes/no)?'])
            if i == 0:
                child.sendline(self.PASSWD)
            elif i == 1:
                child.sendline('yes')
                child.expect('assword: ')
                child.sendline(self.PASSWD)
        except pexpect.EOF:
            child.close()
        child.expect('#')
        child.sendline(command)
        child.expect('#')
        print child.before

    def scpfile(self,localpath,remotepath):
        child = pexpect.spawn("scp %s %s@%s:%s"%(localpath,self.USER,self.IP,remotepath))
        print_Highlighted_Red(self.IP)
        try:
            i = child.expect(['assword: ', 'continue connecting (yes/no)?'])
            if i == 0:
                child.sendline(self.PASSWD)
                child.read()
            elif i == 1:
                child.sendline('yes')
                child.expect('assword: ')
                child.sendline(self.PASSWD)
                child.read()
        except pexpect.EOF:
            child.close()
        print child.before


global ip_list_file
ip_list_file = '/root/batexec/ip_password.conf'
#ip地址路径
#
# 注意：你可能需要修改ip_list_file变量的值来指向合法的配置文件
# 警告：密码写到明文可能不安全，由此带来的风险，需要你自己把控
if len(sys.argv) == 3:
    ipstr = sys.argv[1]
    command = sys.argv[2]
    loginfolist = format_ip_str(ipstr)
    for loginfo in loginfolist:
        ip = loginfo.split(' ')[0]
        user = loginfo.split(' ')[1]
        passwd = loginfo.split(' ')[2]
        batexec = Batexec(ip,user,passwd)
        batexec.cmd(command)
elif len(sys.argv) == 4:
    ipstr = sys.argv[1]
    localpath = sys.argv[2]
    remotepath = sys.argv[3]
    loginfolist = format_ip_str(ipstr)
    for loginfo in loginfolist:
        ip = loginfo.split(' ')[0]
        user = loginfo.split(' ')[1]
        passwd = loginfo.split(' ')[2]
        batexec = Batexec(ip,user,passwd)
        batexec.scpfile(localpath,remotepath)
else:
    print '输入有误'
