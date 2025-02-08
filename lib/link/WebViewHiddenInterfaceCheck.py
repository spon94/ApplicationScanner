from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class WebViewHiddenInterfaceCheck(Base):
    def scan(self):
        set_values_for_key(key='WEBVIEWHIDDENCHECKTITLE', zh='有风险的Webview系统隐藏接口',
                           en='activity component implicit call risk detection')
        set_values_for_key(key='WEBVIEWHIDDENCHECKINFO', zh='检测App程序中是否已经移除有风险的Webview系统隐藏接口',
                           en='Detect whether there is a risk of implicit calling of the activity component in Apk')

        TITLE = get_value('WEBVIEWHIDDENCHECKTITLE')
        LEVEL = 3
        INFO = get_value('WEBVIEWHIDDENCHECKINFO')

        results = []
        
        yml = f'{self.appPath}/apktool.yml'
        min_sdkVer = 0
        with open(yml, mode='r') as f:
            io = f.read()
            strArr = str(io).split('\n')
            for s in strArr:
                if 'minSdkVersion' in s:
                    min_sdkVer = int(s.split(':')[-1].lstrip().replace("'", ''))
        
        # https://blog.csdn.net/qq_35993502/article/details/120454045
        # 最小兼容版本大于等于17，则不存在此风险
        if min_sdkVer >= 17:
          results.append('Safe')
        else:
          # 全局搜索是否使用webview
          strline = cmdString(
            f'grep -r "Landroid/webkit/WebView"'
          )
          paths = getSmalis(os.popen(strline).readlines())
          # 若使用则搜索是否移除不安全接口
          if paths != []:
            strline = cmdString(
              f'grep -r "removeJavascriptInterface"'
            )
            remove_funcs = getSmalis(os.popen(strline).readlines())
            # 若未调用改接口则存在风险
            if remove_funcs == []:
              results.append('Dangerous')

        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(WebViewHiddenInterfaceCheck)