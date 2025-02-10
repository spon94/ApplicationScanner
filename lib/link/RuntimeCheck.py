from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class RuntimeCheck(Base):
    def scan(self):
        
        # Vpn 调用函数
        vpn_functions = [
            'Ljava/lang/Runtime;->exec',
            'Ljava/lang/Runtime;->getRuntime'
        ]

        set_values_for_key(key='RUNTIMECHECKTITLE', zh='运行其他可执行程序漏洞',
                           en='SQL injection detection')
        set_values_for_key(key='RUNTIMECHECKINFO', zh='检测App是否存在运行其他可执行程序漏洞',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('RUNTIMECHECKTITLE')
        LEVEL = 1
        INFO = get_value('RUNTIMECHECKINFO')

        results = []
        for function in vpn_functions:
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
                        for pattern in vpn_functions:
                            if pattern in line:
                                result = name + ' : ' + str(i + 1) + line
                                if result not in results:
                                    results.append(result)
        if len(results) == 0:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(RuntimeCheck)
