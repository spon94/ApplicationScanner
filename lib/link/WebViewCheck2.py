from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class WebViewCheck2(Base):
    def scan(self):
        strline = cmdString(
            'grep -r "Landroid/webkit/WebView" ' + self.appPath)
        paths = getSmalis(os.popen(strline).readlines())
        resultsXSS = []
        resultsFileAccess = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                hasExp = True
                vvv = 3
                lines.reverse()
                for i in range(count):
                    line = lines[i]
                    # XSS 检测
                    if 'Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end].split(',')[-1]
                        for j in range(i, count):
                            ll = lines[j]
                            if v in ll and '0x1' in ll and 'const' in ll:
                                result = name + ' : ' + str(count - i)
                                if result not in resultsXSS:
                                    resultsXSS.append(result)
                                break
                    # setAllowFileAccess 检测
                    if 'Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end].split(',')[-1]
                        for j in range(i, count):
                            ll = lines[j]
                            if v in ll and '0x1' in ll and 'const' in ll:
                                result = name + ' : ' + str(count - i)
                                if result not in resultsFileAccess:
                                    resultsFileAccess.append(result)
                                break

        set_values_for_key(key='WEBXSSCHECKTITLE', zh='WebView跨站脚本攻击检测',
                           en='WebView  XSS detection')
        set_values_for_key(key='WEBXSSCHECHINFO', zh='检测App程序是否存在Webview跨站脚本攻击风险',
                           en="Detect whether there is a risk of Webview remote XSSging in the App program")
        Info(key=self.__class__, title=get_value('WEBXSSCHECKTITLE'), level=3, info=get_value('WEBXSSCHECHINFO'),
             result='\n'.join(resultsXSS)).description()

        set_values_for_key(key='WEBREMOVECHECKTITLE', zh='允许Webview访问本地任意脚本',
                           en='WebView did not remove the risky system hidden interface vulnerabilities')
        set_values_for_key(key='WEBREMOVECHECHINFO', zh='检测App程序中是否允许Webview访问本地任意脚本',
                           en="Check whether there is an unremoved hidden interface of the Webview system in the App program")
        Info(key=self.__class__, title=get_value('WEBREMOVECHECKTITLE'), level=3, info=get_value('WEBREMOVECHECHINFO'),
             result='\n'.join(resultsFileAccess)).description()


register(WebViewCheck2)
