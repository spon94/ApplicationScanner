from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class LogUsageCheck(Base):
    def scan(self):
        
        # 定义捕获日志等级
        log_patterns = [
            'Landroid/util/Log;->d',  # Log.d DEBUG
            # 'Landroid/util/Log;->e',  # Log.e ERROR
            # 'Landroid/util/Log;->i',  # Log.i INFO
            # 'Landroid/util/Log;->v',  # Log.v VERBOSE
            # 'Landroid/util/Log;->w',  # Log.w WARN
            'Landroid/util/log;->getStackTraceString', # log.getStrackTraceString 从 Throwable 获取可记录堆栈跟踪
            # 'Landroid/util/Log;->wtf', # Log.wtf What a Terrible Failure 报告一个不应该发生的情况
        ]

        set_values_for_key(key='LOGUSAGETITLE', zh='LOG使用检测',
                           en='SQL injection detection')
        set_values_for_key(key='SQLCHECHINFO', zh='检测App是否存在调试日志函数的调用',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('LOGUSAGETITLE')
        LEVEL = 1
        INFO = get_value('SQLCHECHINFO')

        strline = cmdString(
            f'grep -ir "log" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name  = getFileName(path)
                for i in range(count):
                    line = lines[i]
                    for pattern in log_patterns:
                        if pattern in line:
                            result = name + ' : ' + str(i + 1)
                            if result not in results:
                                results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(LogUsageCheck)
