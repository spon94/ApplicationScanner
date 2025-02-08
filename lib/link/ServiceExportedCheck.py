from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class ServiceExportedCheck(Base):
    def scan(self):
        set_values_for_key(key='SERVICEEXPORTEDTITLE', zh='Service组件导出风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='SERVICEEXPORTEDINFO', zh='检测Apk中是否存在Service组件导出风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('SERVICEEXPORTEDTITLE')
        LEVEL = 1
        INFO = get_value('SERVICEEXPORTEDINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for service in root.iter('service'):
            if service.get('{http://schemas.android.com/apk/res/android}exported') == 'true':
                results.append(service.get('{http://schemas.android.com/apk/res/android}name'))
        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ServiceExportedCheck)