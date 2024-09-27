from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class UnitTestCheck(Base):
    def scan(self):
        set_values_for_key(key='UNITTESTCHECKTITLE', zh='单元测试配置风险检测',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='UNITTESTCHECHINFO', zh='检测Apk中是否存在单元测试配置的风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('UNITTESTCHECKTITLE')
        LEVEL = 2
        INFO = get_value('UNITTESTCHECHINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # 单元测试配置项
        test_related_attributes = [
            '{http://schemas.android.com/apk/res/android}testOnly',
            '{http://schemas.android.com/apk/res/android}debuggable'
        ]

        risks = []
        for attr in test_related_attributes:
            if root.get(attr) == 'true':
                risks.append(attr)

        # 检查是否存在测试相关的组件
        application = root.find('application')
        if application is not None:
            for component in application.findall('*'):
                if 'test' in component.tag or 'Test' in component.tag:
                    risks.append(component.tag)

        if risks:
            risks.append('Dangerous')
        else:
            risks.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(risks)).description()


register(UnitTestCheck)
