from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class ShareUserIdCheck(Base):
    def scan(self):
        set_values_for_key(key='SHAREUSERIDTITLE', zh='shareUserID 配置',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='SHAREUSERIDINFO', zh='检测Apk中是否存在 shareUserID 配置风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('SHAREUSERIDTITLE')
        LEVEL = 1
        INFO = get_value('SHAREUSERIDINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        shared_user_id = root.get('{http://schemas.android.com/apk/res/android}sharedUserId')
        if shared_user_id is not None:
            results.append('Dangerous')
        else:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ShareUserIdCheck)