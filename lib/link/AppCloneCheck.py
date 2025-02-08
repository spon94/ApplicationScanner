from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class AppCloneCheck(Base):
    def scan(self):
        set_values_for_key(key='APPCLONETITLE', zh='应用克隆漏洞攻击',
                           en='activity component implicit call risk detection')
        set_values_for_key(key='APPCLONEINFO', zh='检测Apk中是否存在应用克隆漏洞攻击风险',
                           en='Detect whether there is a risk of implicit calling of the activity component in Apk')

        TITLE = get_value('APPCLONETITLE')
        LEVEL = 3
        INFO = get_value('APPCLONEINFO')

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        results = []
        exported_activities = []
        webview_activities = []

        # 1、筛选可导出的 activity
        for activity in root.iter('activity'):
            if activity.get('{http://schemas.android.com/apk/res/android}exported') == 'true':
                exported_activities.append(activity.get('{http://schemas.android.com/apk/res/android}name'))

        # 2、进一步筛选存在 webview 相关的 activity 
        for activity in exported_activities:
            strline = cmdString(
                f'grep -r ".class public {activity}"'
            )
            paths = getSmalis(os.popen(strline).readlines())
            for path in paths:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    count = len(lines)
                    name = getFilename(path)
                    for i in range(count):
                        line = lines[i]
                        if "Landroid/webkit/WebView" in line:
                            result = name + ' : ' + str(i + 1) + line
                            if name not in webview_activities:
                                webview_activities.append(name)
                            if result not in results:
                                    results.append(result)

        if results == []:
            results.append('Safe')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(AppCloneCheck)