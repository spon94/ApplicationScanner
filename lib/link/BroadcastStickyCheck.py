# https://blog.csdn.net/u011506413/article/details/54095148
from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class BroadcastStickyCheck(Base):
    def scan(self):
        set_values_for_key(key='BROADCASTSTICKYRMISSIONTITLE', zh='Provider writePermission风险',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='BROADCASTSTICKYRMISSIONINFO', zh='检测Apk中是否存在Provider writePermission风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('BROADCASTSTICKYRMISSIONTITLE')
        LEVEL = 1
        INFO = get_value('BROADCASTSTICKYRMISSIONINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        for provider in root.iter('provider'):
            if provider.get('{http://schemas.android.com/apk/res/android}writePermission'):
                if not provider.get('{http://schemas.android.com/apk/res/android}readPermission'):
                    results.append('Dangerous')
                    break
        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(BroadcastStickyCheck)