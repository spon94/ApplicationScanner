from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *

class CallbackCheck(Base):
    def scan(self):
        # Callback 调用函数
        callback_functions = [
            'Callback',
            'invoke'
        ]

        set_values_for_key(key='CALLBACKCHECKTITLE', zh='Callback函数调用检测',
                           en='Callback function call detection')
        set_values_for_key(key='CALLBACKCHECKINFO', zh='检测App是否存在Callback函数的调用',
                           en="Detect whether there are callback function calls in the App")

        TITLE = get_value('CALLBACKCHECKTITLE')
        LEVEL = 1
        INFO = get_value('CALLBACKCHECKINFO')

        results = []
        strline = cmdString(
            f'grep -r "public onGeolocationPermissionsShowPrompt"'
        )
        paths = getSmalis(os.popen(strline).readlines())
        for path in paths:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                for i in range(count):
                    line = lines[i]
                    if 'public onGeolocationPermissionsShowPrompt' in line:
                      for pattern in callback_functions:
                          if pattern in line:
                              result = name + ' : ' + str(i + 1) + line
                              if result not in results:
                                  results.append(result)

        if len(results) == 0:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()

register(CallbackCheck)
