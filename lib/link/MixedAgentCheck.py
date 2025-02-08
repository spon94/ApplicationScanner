from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class MixedAgentCheck(Base):
    def scan(self):
        
        # Vpn 调用函数
        functions = [
            'checkCallingOrSelfPermission',
            'checkCallingOrSelfUriPermission',
        ]

        set_values_for_key(key='MIXEDAGENTTITLE', zh='混淆代理人攻击风险',
                           en='SQL injection detection')
        set_values_for_key(key='MIXEDAGENTINFO', zh='检测App是否存在混淆代理人攻击风险',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('MIXEDAGENTTITLE')
        LEVEL = 1
        INFO = get_value('MIXEDAGENTINFO')

        results = []
        for function in functions:
            strline = cmdString(
                f'grep -r "{function}" {self.appPath}'
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


register(MixedAgentCheck)
