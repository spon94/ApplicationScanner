# https://www.kancloud.cn/yelbee111/annhub/987942#7_Intent_Scheme_URL__05007_163
from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *

class IntentSchemeURLCheck(Base):
    def scan(self):
        # 安全使用Intent.parseUri函数,intent至少包含以下三个策略
        functions = [
            'Landroid/content/Intent;->addCategory',
            'Landroid/content/Intent;->setComponent',
            'Landroid/content/Intent;->setSelector'
        ]

        set_values_for_key(key='INTENTSCHEMAURLCHECKTITLE', zh='Intent Scheme URL攻击漏洞',
                           en='Callback function call detection')
        set_values_for_key(key='INTENTSCHEMAURLCHECKINFO', zh='检测App是否存在Intent Scheme URL攻击漏洞',
                           en="Detect whether there are callback function calls in the App")

        TITLE = get_value('INTENTSCHEMAURLCHECKTITLE')
        LEVEL = 2
        INFO = get_value('INTENTSCHEMAURLCHECKINFO')

        results = []
        strline = cmdString(
            f'grep -Ir "Landroid/content/Intent;->parseUri" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        for path in paths:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                # 查找起点与终点
                method_start = 0
                method_end = 0
                for i in range(count):
                    line = lines[i]
                    if 'Landroid/content/Intent;->parseUri' in line:
                      # 开始搜索是否调用安全函数，'.end method'作为查找终点
                      method_start = i
                      for j in range(i,count):
                        line = lines[j]
                        if '.end method' in line:
                          method_end = j
                # 找到安全函数的次数，等于安全函数的数量即为通过安全检测
                find_flag = 0
                for pattern in functions:
                  for k in range(method_start,method_end):
                    line = lines[k]
                    if pattern in line:
                      find_flag += 1
                      break
                
                # 判断是否找到全部安全函数的声明
                if find_flag < len(functions):
                  result = name + ' : ' + str(method_start + 1) + lines[method_start]
                  if result not in results:
                    results.append(result)

        if len(results) == 0:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()

register(IntentSchemeURLCheck)
