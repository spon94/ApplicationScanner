from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import xml.etree.ElementTree as ET


class HiddenServiceCheck(Base):
    def scan(self):
        set_values_for_key(key='SERVICECHECKTITLE', zh='Service组件隐式调用风险检测',
                           en='Service component implicit call risk detection')
        set_values_for_key(key='SERVICECHECHINFO', zh='检测Apk中的Service组件是否存在隐式调用的风险',
                           en='Detect whether there is a risk of implicit calling of the Service component in Apk')

        TITLE = get_value('SERVICECHECKTITLE')
        LEVEL = 1
        INFO = get_value('SERVICECHECHINFO')
        results = []

        manifest_path = f'{self.appPath}/AndroidManifest.xml'
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        # 提取权限
        permissions = []
        for perm in root.findall('uses-permission'):
            permissions.append(perm.get('{http://schemas.android.com/apk/res/android}name'))

        # 提取activity和其他组件
        activities = []
        services = []
        receivers = []

        application = root.find('application')
        if application is not None:
            for activity in application.findall('activity'):
                activities.append(activity.get('{http://schemas.android.com/apk/res/android}name'))
            for service in application.findall('service'):
                services.append(service.get('{http://schemas.android.com/apk/res/android}name'))
            for receiver in application.findall('receiver'):
                receivers.append(receiver.get('{http://schemas.android.com/apk/res/android}name'))
        
        # 自启动权限
        auto_start_permission = 'android.permission.RECEIVE_BOOT_COMPLETED' in permissions

        # launcher
        has_launcher = False
        for activity in activities:
            if 'MAIN' in activity and 'LAUNCHER' in activity:
                has_launcher = True
                break

        # 静态广播监听系统启动
        has_boot_receiver = 'android.intent.action.BOOT_COMPLETED' in receivers

        # service组件
        has_services = len(services) > 0

        if auto_start_permission and has_launcher and not has_boot_receiver and not has_services:
            results.append('Safe')
        else:
            results.append('Dangerous')

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(HiddenServiceCheck)
