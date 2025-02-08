from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class HttpsArbitraryHostCheck(Base):
    def scan(self):
        
        # 定义捕获日志等级
        log_patterns = [
            
        ]

        set_values_for_key(key='HttpsArbitraryHostCheck', zh='Https 任意主机名校验',
                           en='SQL injection detection')
        set_values_for_key(key='HTTPSARBITRARYHOSTINFO', zh='检测Https是否对服务器主机名进行校验',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('HttpsArbitraryHostCheck')
        LEVEL = 2
        INFO = get_value('HTTPSARBITRARYHOSTINFO')

        strline = cmdString(
            f'grep -ir "implements Ljavax/net/ssl/HostnameVerifier" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        # 检测是否存在 try-catch 声明
        sub_result = ''
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name  = getFileName(path)
                for i in range(count):
                    if 'method public final verify' in lines[i]:
                        method_start = i
                        for j in range(i,count):
                            if 'end method' in lines[j]:
                                method_end = j
                        for k in range(i,j):
                            if 'invoke-static {v0' in lines[k]:
                                sub_result = 'PASS'
                                break
                        line = lines[i]
                        result = name + ' : ' + str(i + 1)
                        break
                if 'PASS' in sub_result:
                    results.append('Safe')
                else:
                    results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(HttpsArbitraryHostCheck)
