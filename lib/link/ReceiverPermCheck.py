from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *

# https://blog.csdn.net/weixin_37600397/article/details/141461354
# 指定了权限的receiver参数为五个，未指定的为三个
class ReceiverPermCheck(Base):
    def scan(self):
        
        # Vpn 调用函数
        functions = [
            'Landroid/content/Context;->registerReceiver'
        ]

        set_values_for_key(key='RECEIVERCHECKTTITLE', zh='Broadcast权限未指定风险',
                           en='SQL injection detection')
        set_values_for_key(key='RECEIVERCHECKTINFO', zh='检测App是否存在Broadcast权限未指定风险',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('RECEIVERCHECKTTITLE')
        LEVEL = 1
        INFO = get_value('RECEIVERCHECKTINFO')

        results = []
        for function in functions:
            strline = cmdString(
                f'grep -Iiwr "{function}" {self.appPath}'
            )
            paths = getSmalis(os.popen(strline).readlines())
            for path in paths:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    count = len(lines)
                    name  = getFileName(path)
                    for i in range(count):
                        line = lines[i]
                        for pattern in functions:
                            if (pattern in line):
                                if "Ljava/lang/String" not in line:
                                  result = name + ' : ' + str(i + 1) + line
                                  if result not in results:
                                      results.append(result)
        if len(results) == 0:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()

register(ReceiverPermCheck)
