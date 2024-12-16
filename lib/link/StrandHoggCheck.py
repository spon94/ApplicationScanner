from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class StrandHoggCheck(Base):
    def scan(self):
        set_values_for_key(key='STRNDHOGGTITLE', zh='StrandHogg漏洞',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='STRNDHOGGINFO', zh='检测Apk中是否存在StrandHogg漏洞',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('STRNDHOGGTITLE')
        LEVEL = 1
        INFO = get_value('STRNDHOGGINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        compileSdkVersion = root.get('{http://schemas.android.com/apk/res/android}compileSdkVersion')
        if compileSdkVersion is not None:
            if int(compileSdkVersion) < 30:
                application = root.find('application')
                taskAffinity = application.get('{http://schemas.android.com/apk/res/android}taskAffinity')
                if taskAffinity != '' :
                    results.append('Dangerous')
            else:
                results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(StrandHoggCheck)