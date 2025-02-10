from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class SocketSecurity(Base):
    def scan(self):

        set_values_for_key(key='SOCKETSECURITY', zh='Socket 通信安全风险',
                           en='SQL injection detection')
        set_values_for_key(key='SOCKETSECURITYTINFO', zh='检测Https是否存在Socket 通信安全风险',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('SOCKETSECURITY')
        LEVEL = 2
        INFO = get_value('SOCKETSECURITYTINFO')

        strline = cmdString(
            f'grep -Iir "Ljavax/net/ssl/SSLSocket" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        # 检测是否调用SSLSocketFactory
        sub_result = ''
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name  = getFileName(path)
                for i in range(count):
                    if 'Ljavax/net/ssl/SSLSocketFactory' in lines[i]:
                        result = name + ':Safe'
                        break
                if 'FIND' in sub_result:
                    results.append(result)
                else:
                    result = name + ':Danger'
                    results.append(result)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(SocketSecurity)
