from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class InputMonitoringCheck(Base):
    def scan(self):
        set_values_for_key(key='INPUTMONITORTITLE', zh='输入监听风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='INPUTMONITORINFO', zh='检测Apk中是否存在输入监听风险,AndroidManifest.xml文件中设置android:windowSoftInputMode="adjustResize"属性，则存在风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('INPUTMONITORTITLE')
        LEVEL = 1
        INFO = get_value('INPUTMONITORINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for activity in root.iter('activity'):
            if activity.get('{http://schemas.android.com/apk/res/android}windowSoftInputMode') == 'adjustResize':
                results.append('Dangerous')
                break
        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(InputMonitoringCheck)