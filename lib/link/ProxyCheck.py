from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class ProxyCheck(Base):
    def scan(self):
        set_values_for_key(key='PROXYCHECK', zh='联网环境检测',
                           en='HTTP Plaintext Check')
        set_values_for_key(key='PROXYCHECKINFO', zh='检测App是否具有检查系统网络代理服务器信息的特征代码',
                           en="Detect whether there are usage conditions for SQL Cipher")

        TITLE = get_value('PROXYCHECK')
        LEVEL = 2
        INFO = get_value('PROXYCHECKINFO')
        results = []
        strline = cmdString(
            'grep -Ir "getProxy"' + self.appPath
        )
        paths = getSmalis(os.popen(strline).readlines())
        if len(paths) != 0:
            results.append('Safe')
        else:
            results.append('Danger')
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()

register(ProxyCheck)
