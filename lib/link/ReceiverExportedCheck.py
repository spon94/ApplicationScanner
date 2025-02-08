from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class ReceiverExportedCheck(Base):
    def scan(self):
        set_values_for_key(key='SRECEIVEREXPORTEDTITLE', zh='Receiver组件导出风险',
                           en='Receiver component implicit call risk detection')
        set_values_for_key(key='SRECEIVEREXPORTEDINFO', zh='检测Apk中是否存在Receiver组件导出风险',
                           en='Detect whether there is a risk of implicit calling of the Receiver component in Apk')

        TITLE = get_value('SRECEIVEREXPORTEDTITLE')
        LEVEL = 1
        INFO = get_value('SRECEIVEREXPORTEDINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for receiver in root.iter('receiver'):
            if receiver.get('{http://schemas.android.com/apk/res/android}exported') == 'true':
                results.append(receiver.get('{http://schemas.android.com/apk/res/android}name'))
        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ReceiverExportedCheck)