from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class HttpsServerCheck(Base):
    def scan(self):
        
        # 定义捕获日志等级
        log_patterns = [
            
        ]

        set_values_for_key(key='HTTPSSERVERCHECK', zh='Https 证书校验检测',
                           en='SQL injection detection')
        set_values_for_key(key='HTTPSSERVERINFO', zh='检测Https是否对服务器证书进行校验',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('HTTPSSERVERCHECK')
        LEVEL = 2
        INFO = get_value('HTTPSSERVERINFO')

        strline = cmdString(
            f'grep -ir ".implements Ljavax/net/ssl/X509TrustManager" {self.appPath}'
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
                    if 'method public checkClientTrusted' in lines[i]:
                        method_start = i
                        for j in range(i,count):
                            if 'end method' in lines[j]:
                                method_end = j
                        for k in range(i,j):
                            if 'Ljava/security/cert/CertificateException; {:try_start_0 .. :try_end_0} :catch_0' in lines[k]:
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


register(HttpsServerCheck)
