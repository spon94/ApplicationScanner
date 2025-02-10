from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class WebViewBrowserCheck(Base):
    def scan(self):
        set_values_for_key(key='BROWSERCHECKTITLE', zh='浏览器调用漏洞',
                           en='activity component implicit call risk detection')
        set_values_for_key(key='BROWSERCHECKINFO', zh='检测Apk中是否存在浏览器调用漏洞',
                           en='Detect whether there is a risk of implicit calling of the activity component in Apk')

        TITLE = get_value('BROWSERCHECKTITLE')
        LEVEL = 2
        INFO = get_value('BROWSERCHECKINFO')

        results = []
        strline = cmdString(
            # 检测是否启用 JavaScript 编程接口
            f'grep -Ir "Landroid/webkit/WebSettings;->setJavaScriptEnabled" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                for i in range(count):
                    line = lines[i]
                    # 检测是否通过WebViewSetting获取浏览器信息
                    if "Landroid/webkit/WebSettings;->getUserAgentString" in line:
                        result = path + ' : ' + line
                        if result not in results:
                                results.append(result)

        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(WebViewBrowserCheck)