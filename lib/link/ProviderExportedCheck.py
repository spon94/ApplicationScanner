from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class ProviderExportedCheck(Base):
    def scan(self):
        set_values_for_key(key='PROVIDEREXPORTEDTITLE', zh='Provider组件导出风险',
                           en='Provider component implicit call risk detection')
        set_values_for_key(key='PROVIDEREXPORTEDINFO', zh='检测Apk中是否存在Provider组件导出风险',
                           en='Detect whether there is a risk of implicit calling of the Provider component in Apk')

        TITLE = get_value('PROVIDEREXPORTEDTITLE')
        LEVEL = 1
        INFO = get_value('PROVIDEREXPORTEDINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for provider in root.iter('provider'):
            if provider.get('{http://schemas.android.com/apk/res/android}exported') == 'true':
                results.append(provider.get('{http://schemas.android.com/apk/res/android}name'))
        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ProviderExportedCheck)