from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class WebviewCertificateCheck(Base):
    def scan(self):

        set_values_for_key(key='WEBVIEWCERTCHECK', zh='webview绕过证书校验漏洞',
                           en='SQL injection detection')
        set_values_for_key(key='WEBVIEWCERTINFO', zh='检测Https是否存在webview绕过证书校验漏洞',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('WEBVIEWCERTCHECK')
        LEVEL = 2
        INFO = get_value('WEBVIEWCERTINFO')

        strline = cmdString(
            f'grep -Iir "method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        # 检测是否存在 handler.processed() 声明
        sub_result = ''
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name  = getFileName(path)
                for i in range(count):
                    if 'method public onReceivedSslError' in lines[i]:
                        method_start = i
                        for j in range(i,count):
                            if 'end method' in lines[j]:
                                method_end = j
                        for k in range(i,j):
                            if 'Landroid/webkit/SslErrorHandler;->proceed()V' in lines[k]:
                                sub_result = 'FIND'
                                break
                        line = lines[i]
                        result = name + ' : ' + str(i + 1)
                        break
                if 'FIND' in sub_result:
                    results.append(result)
                else:
                    results.append('Safe')
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(WebviewCertificateCheck)
