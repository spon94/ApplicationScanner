from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *

#https://learn.microsoft.com/zh-cn/dotnet/api/android.content.contentprovider.openfile?view=net-android-34.0
class ContentProviderCheck(Base):
    def scan(self):
        
        # 调用函数
        functions = [
            'Landroid/content/ContentProvider;->openFile'
        ]

        set_values_for_key(key='BROADCASTCHECKTTITLE', zh='ContentProvider访问路径不安全配置风险',
                           en='SQL injection detection')
        set_values_for_key(key='BROADCASTCHECKTINFO', zh='检测App是否存在ContentProvider访问路径不安全配置风险',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('BROADCASTCHECKTTITLE')
        LEVEL = 1
        INFO = get_value('BROADCASTCHECKTINFO')

        results = []
        for function in functions:
            strline = cmdString(
                f'grep -Ir "{function}" {self.appPath}'
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
                                result = name + ' : ' + str(i + 1) + line
                                if result not in results:
                                    results.append(result)
        if len(results) == 0:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()

register(ContentProviderCheck)
