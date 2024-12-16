from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class FunctionCallCheck(Base):
    def scan(self):
        
        # 定义捕获日志等级
        sensitive_functions = [
            'Landroid/app/ActivityManager;->getRunningTasks',
            'Landroid/app/ActivityManager;->getRunningAppProcesses',
            'Landroid/telephony/TelephonyManager;->getNetworkOperator',
            'Landroid/telephony/TelephonyManager;->getPhoneType',
            'Landroid/telephony/TelephonyManager;->getSimOperator',
            'Landroid/telephony/TelephonyManager;->listen',
            'Landroid/location/LocationManager;->getLastKnownLocation',
            'Landroid/hardware/Camera;->setPreviewDisplay'
        ]

        set_values_for_key(key='FUNCTIONCALLTITLE', zh='敏感函数调用检测',
                           en='SQL injection detection')
        set_values_for_key(key='FUNCTIONCALLINFO', zh='检测App是否存在敏感函数的调用',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('FUNCTIONCALLTITLE')
        LEVEL = 1
        INFO = get_value('FUNCTIONCALLINFO')

        results = []
        for function in sensitive_functions:
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
                        for pattern in sensitive_functions:
                            if pattern in line:
                                result = name + ' : ' + str(i + 1) + line
                                if result not in results:
                                    results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(FunctionCallCheck)
