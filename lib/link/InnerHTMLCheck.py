from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *

class InnerHTMLCheck(Base):
    def scan(self):
        set_values_for_key(key='INNERHTMLCHECKTITLE', zh='InnerHTML的XSS攻击漏洞',
                           en='JavaScript resource file leak detection')
        set_values_for_key(key='INNERHTMLCHECHINFO', zh='检测Apk中是否存在InnerHTML的XSS攻击漏洞',
                           en='Detect whether there is a risk of JavaScript file information leakage in Apk')

        TITLE = get_value('INNERHTMLCHECKTITLE')
        LEVEL = 3
        INFO = get_value('INNERHTMLCHECHINFO')

        strline = cmdString(f"find {self.appPath} \( -name '*.js' -o -name '*.html' -o -name '*.bundle' \) | grep -i inner")
        out = os.popen(strline).readlines()
        results = []
        for line in out:
            filepath = line[:-1]
            if filepath not in results:
                results.append(filepath)
        
        if results == []:
          results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(InnerHTMLCheck)
