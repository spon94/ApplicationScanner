from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class NetworkSecCheck(Base):
    def scan(self):
        set_values_for_key(key='NETSECCONFTITLE', zh='未配置网络安全属性风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='NETSECCONFINFO', zh='检测Apk中是否存在未配置网络安全属性风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('NETSECCONFTITLE')
        LEVEL = 2
        INFO = get_value('NETSECCONFINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        application = root.find('application')
        allow_backup = application.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
        if allow_backup is not None:
            results.append('Safe')
        else:
            results.append('Dangerous')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(NetworkSecCheck)