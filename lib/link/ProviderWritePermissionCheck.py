from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class ProviderWritePermissionCheck(Base):
    def scan(self):
        set_values_for_key(key='PROVIDERPERMISSIONTITLE', zh='粘滞广播使用风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='PROVIDERPERMISSIONINFO', zh='检测Apk中是否存在粘滞广播使用风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('PROVIDERPERMISSIONTITLE')
        LEVEL = 1
        INFO = get_value('PROVIDERPERMISSIONINFO')
        results = []
        permissions = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for perm in root.iter('uses-permission'):
            permissions.append(perm.get('{http://schemas.android.com/apk/res/android}name'))
                
        
        
        if "BROADCAST_STICKY" in permissions:
            results.append('Dangerous')
        else:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ProviderWritePermissionCheck)