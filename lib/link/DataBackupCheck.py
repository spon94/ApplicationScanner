from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class DataBackupCheck(Base):
    def scan(self):
        set_values_for_key(key='DATABACKUPTITLE', zh='数据任意备份风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='DATABACKUPINFO', zh='检测Apk中是否存在数据任意备份风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('DATABACKUPTITLE')
        LEVEL = 1
        INFO = get_value('DATABACKUPINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        application = root.find('application')
        allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup')
        if allow_backup is not None:
            if allow_backup.lower() == 'true':
                results.append('Dangerous')
            else:
                results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(DataBackupCheck)