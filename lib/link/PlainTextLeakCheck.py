from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class PlainTextLeakCheck(Base):
    def scan(self):

        # 排除在筛选范围，减少审计工作量
        whitelist = [
            'yealink'
        ]
        # 定义捕获日志等级
        keywords = [

            "password",
            "passwd",
            "pwd",
        ]

        set_values_for_key(key='PLAINTEXTLEAKTITLE', zh='密码明文信息检测',
                           en='SQL injection detection')
        set_values_for_key(key='PLAINTEXTLEAKINFO', zh='检测App是否存在密码明文信息',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('PLAINTEXTLEAKTITLE')
        LEVEL = 1
        INFO = get_value('PLAINTEXTLEAKINFO')

        results = []
        for word in keywords:
            strline = cmdString(
                f'grep -ir "{word}" {self.appPath} | grep -v "{ "|".join(whitelist) }"'
            )
            paths = getSmalis(os.popen(strline).readlines())
            for path in paths:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    count = len(lines)
                    name  = getFileName(path)
                    for i in range(count):
                        line = lines[i]
                        for pattern in keywords:
                            if pattern in line:
                                result = name + ' : ' + str(i + 1) + line
                                if result not in results:
                                    results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(PlainTextLeakCheck)
