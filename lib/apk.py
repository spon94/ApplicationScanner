#!/usr/bin/python3
# -*- coding:utf-8 -*-
import shutil
import traceback
import xml.dom.minidom
from pathlib import Path

from lib.info import Info
from lib.tools import *
from lib.translation import *

# __file__是Python中的一个内置变量，表示当前脚本的文件路径。
# Path(__file__)将该文件路径转换为Path对象，以便进行路径操作。
# Path对象的.parents属性返回一个包含所有父级目录的路径列表。通过索引[1]，选择了父级目录列表中的第一个父级目录。
apktool = str(Path(__file__).parents[1] / 'ThirdTools/apktool.jar')
apksigner = str(Path(__file__).parents[1] / 'ThirdTools/apksigner.jar')
bundletool = str(Path(__file__).parents[1] / 'ThirdTools/bundletool.jar')
certificate = str(Path(__file__).parents[1] / 'ThirdTools/Certificate')


# 存放有关 apk 扫描类
# Android 文件夹中，除 inti.py 文件外，均继承自 Base.py 文件夹中定义的 Base 类
# 对 scan 方法进行重写后，使用 register() 完成注册工作，写入 scanners 字典中
scanners = {}


def register(scanner_class):
    scanners[scanner_class.__name__] = scanner_class


def scanner(scanner_key):
    scanner_class = scanners.get(scanner_key)
    return None if scanner_class is None else scanner_class


def import_scanners(scanners_imports):
    for runner_import in scanners_imports:
        __import__(runner_import)

from . import Android # 执行导入包到 scanners

def apkScan(inputfile, save):
    if inputfile.endswith('.apk'):
        # 解压apk包
        # [magenta],[bold magenta] 指定文本样式
        console.print('\n[magenta]Unzip apk [/magenta][bold magenta]' + inputfile + '[/bold magenta]')
        # 从路径中取 apk 文件，并使用6位随机字符串替换apk后缀（用于多次扫描一个apk文件）
        filePath = inputfile.replace('.apk', '').split('/')[-1] + randomStr(6)
        # TODO
        # RunCMD() 为自定义函数，用于处理 linux 命令
        # 解压文件输出到 filePath 变量中，用于下一步处理
        RunCMD(f'java -jar \'{apktool}\' d -f \'{inputfile}\' -o \'{filePath}\' --only-main-classes').execute()
        console.print('[bold green]Finish[/bold green]')
        # 获取 filePath 绝对路径
        filePath = os.path.abspath(filePath)
    else:
        # 解压aab包
        console.print('\n[magenta]Unzip aab [/magenta][bold magenta]' + inputfile + '[/bold magenta]')
        filePath = inputfile.replace('.aab', '').split('/')[-1] + randomStr(6)
        RunCMD(
            f'java -jar \'{bundletool}\' build-apks --mode=universal --bundle=\'{inputfile}\' --output=applicationScanner.apks --ks=\'{certificate}\' --ks-pass=pass:123456 --ks-key-alias=dw --key-pass=pass:123456').execute()
        RunCMD('unzip -o applicationScanner.apks -d ApplicationScannerTemp').execute()
        apkPath = './' + 'ApplicationScannerTemp/universal.apk'
        RunCMD(f'java -jar \'{apktool}\' d -f \'{apkPath}\' -o \'{filePath}\' --only-main-classes').execute()
        console.print('[bold green]Finish[/bold green]')
        os.remove('applicationScanner.apks')
        shutil.rmtree('./ApplicationScannerTemp')
    try:
        # 调用以下函数，获取 apk 文件基本信息
        # TODO
        # apkInfo:
        # permissionAndExport:
        # appSign:
        # fingerPrint:
        apkInfo(filePath)
        permissionAndExport(filePath)
        appSign(inputfile)
        fingerPrint(filePath)


        # TODO
        # 调用 Android 文件夹中的检测函数
        # scanners 示例如下：
            # 'DBCheck': <class 'lib.Android.DBCheck.DBCheck'>
            # 'HiddenIntentCheck': <class 'lib.Android.HiddenIntentCheck.HiddenIntentCheck'>
            # ...(即 Android 文件夹中所存储的各 py 文件名)
        for key in scanners.keys():
            # 将scanner(key)的返回值赋给变量c。
            # 如果scanner(key)返回的值不为None，则条件成立，进入条件语句块
            # 海象运算符在Python 3.8及更高版本中可用
            if c := scanner(key):
                c(filePath).scan()
    except Exception:
        # 在异常处理代码块中打印当前异常的详细信息
        print(traceback.format_exc())

    if not save:
        console.print('\n[bold magenta]Clean cache...[/bold magenta]')
        # shutil 是 Python 的标准库之一，提供了许多对文件和目录进行操作的函数。
        # rmtree() 函数是其中之一，用于删除一个目录及其所有子目录和文件。
        shutil.rmtree(filePath)
        console.print('[bold green]Finish[/bold green]')



# apksigner，apk 签名工具，官方文档：https://developer.android.com/tools/apksigner?hl=zh-cn
def appSign(filePath):
    # java -jar apksigner.jar verify -v --print-certs 解释如下
    # 使用 apksigner.jar 工具显示有关 APK 签名证书的信息，并验证证书签名是否有效，-v 标志详细输出模式
    # 对输出结果字符字符流使用 UTF-8 编码进行解码操作，转换为字符串，遇到无法解码的字符串时，使用 ‘replace’ 替换
    # split 对字符串进行分割，获取字符串列表
    # arr输出示例
        # 'Verifies'
        # 'Verified using v1 scheme (JAR signing): false'
        # 'Verified using v2 scheme (APK Signature Scheme v2): true'
        # 'Verified using v3 scheme (APK Signature Scheme v3): false'
        # 'Verified using v4 scheme (APK Signature Scheme v4): false'
        # 'Verified for SourceStamp: false'
        # 'Number of signers: 1'
        # 'Signer #1 certificate DN: CN=YealinkYms'
        # 'Signer #1 certificate SHA-256 digest: 97f007121aa5c08b8d63ecc5407e5fbcfff7f66f289d6ed3d2223f3bedbc6d7a'
        # 'Signer #1 certificate SHA-1 digest: 5694ed64ae9d2651d7114a008d4e1b6dc30669e0'
        # 'Signer #1 certificate MD5 digest: b5368106f79ab49466b24315dccea5cc'
        # 'Signer #1 key algorithm: RSA'
        # 'Signer #1 key size (bits): 2048'
        # 'Signer #1 public key SHA-256 digest: a334b2bb791a357df8b1de4dbe0c25f968f6785f3c186bfc84d762ea67860e50'
        # 'Signer #1 public key SHA-1 digest: 2a252abb3ef5a121e8a39e0db0612d2a208f7355'
        # 'Signer #1 public key MD5 digest: 094a97b30f5193f0bde4decca9394821'
        # ''
    arr = RunCMD(f'java -jar {apksigner} verify -v --print-certs \'{filePath}\'').execute()[0].decode('utf-8',
                                                                                                      'replace').split(
        '\n')
    result = ''.join(line + '\n' for line in arr if 'WARNING:' not in line)
    if result != "":
        # strip(): 
            # 此函数只会删除头和尾的字符，中间的不会删除。
            # 参数为空：默认删除字符串头和尾的空白字符(包括\n，\r，\t这些)
            # 参数不接受字符串，若传入 strip("abc")，则分别对 'a' 'b' 'c' 进行处理
        # lstrip(): strip() 功能类似，但只对左边内容做处理
        # rstrip(): strip() 功能类似，但只对右边内容做处理
        result.rstrip()
        # TODO
        set_values_for_key(key='ANDROIDSIGNTITLE', zh='签名信息', en='Signature information')
        set_values_for_key(key='ANDROIDSIGNINFO', zh='签名验证详细信息', en='Signature verification details')
        # TODO
        Info(title=get_value('ANDROIDSIGNTITLE'), level=0, info=get_value('ANDROIDSIGNINFO'),
             result=result).description()


def fingerPrint(filePath):
    # 在 META-INF 目录中，可能会包含以 .RSA 后缀结尾的文件。
    # 这些文件是用于数字签名的文件，用于验证 JAR 文件的完整性和真实性。
    # 数字签名是一种加密技术，它使用私钥对文件进行签名，然后使用相应的公钥进行验证。
    # 在开发中，使用数字签名可以确保 JAR 文件没有被篡改或损坏，并且可以验证 JAR 文件的来源。
    # 当你使用包含数字签名的 JAR 文件时，Java 运行时环境会自动验证签名，以确保文件的完整性和安全性。
    strline = f'cd \'{filePath}\'/original/META-INF && (ls | grep *.RSA)'
    # os.popen()函数用于执行系统命令，并返回一个文件对象，
    # 可以通过该文件对象进行读取操作。
    out = os.popen(strline).readlines()
    rsa = ''
    for line in out:
        # 切片操作去除换行符
        # lstrip() 去掉行首的空格或制表符。
        rsa = line[:-1].lstrip()
    if len(rsa) > 0:
        extract_and_display_certificate_info(filePath, rsa)


# TODO Rename this here and in `fingerPrint`
# 使用 Keytool 文件获取证书信息 具体参考：https://www.cnblogs.com/liaojie970/p/4916602.html
def extract_and_display_certificate_info(filePath, rsa):
    # -printcert 查看导出的证书信息
    strline = f'keytool -printcert -file \'{filePath}\'/original/META-INF/{rsa}'
    out = os.popen(strline).readlines()
    result = ''.join(out)
    set_values_for_key(key='ANDROIDCERTTITLE', zh='证书指纹', en='Certificate fingerprint')
    set_values_for_key(key='ANDROIDCERTINFO', zh='证书指纹信息', en='Certificate fingerprint information')
    Info(title=get_value('ANDROIDCERTTITLE'), level=0, info=get_value('ANDROIDCERTINFO'),
         result=result).description()


def permissionAndExport(filePath):
    # AndroidManifest.xml文件包含了应用程序的各种信息，
    # 包括应用程序的包名、版本号、权限要求、组件声明（如活动、服务、广播接收器等）、应用程序的入口点等。
    # 定义了应用程序的基本特性和配置信息，它在应用程序安装时被系统读取，并用于确定应用程序的行为和属性。
    # 系统根据清单文件中的信息来为应用程序分配资源、分配权限、管理应用程序的组件等。
    XMLPath = f'{filePath}/AndroidManifest.xml'
    # xml.dom.minidom模块提供了一种简单的方式来解析和操作XML文档。
    # parse()函数接受一个XML文件的路径作为参数，并返回一个表示整个XML文档的Document对象。
    # 这个对象可以用于访问和操作XML文档的元素、属性和文本等内容。
    tree = xml.dom.minidom.parse(XMLPath)
    root = tree.documentElement
    package = root.getAttribute('package')

    set_values_for_key(key='ANDROIDPACKAGENAMETITLE', zh='包名信息', en='Package Name information')
    set_values_for_key(key='ANDROIDPACKAGENAMEINFO', zh='应用包名信息', en='Application Package Name information')
    set_values_for_key(key='ANDROIDPACKAGENAME', zh='  包名: ', en='  Certificate fingerprint: ')
    Info(title=get_value('ANDROIDPACKAGENAMETITLE'), level=0, info=get_value('ANDROIDPACKAGENAMEINFO'),
         result=(get_value('ANDROIDPACKAGENAME') + package)).description()

    # TODO
    # permissionList 输出示例，字符串列表
        # 'com.htc.launcher.permission.READ_SETTINGS'
        # 'android.permission.ACCESS_FINE_LOCATION'
        # 'android.permission.ACCESS_NOTIFICATION_POLICY'
        # 'me.everything.badger.permission.BADGE_COUNT_READ'
        # 'android.permission.GET_ACCOUNTS'
        # ...
    permissionList = apkPermissionList(root)
    # 对权限内容进行分类，获取各类权限列表
    normalArray, dangerousArray, coreArray, specialArray, newPermissionList = apkPermissionLevel(permissionList)
    if len(normalArray) > 0:
        result = ''.join(
            f'{p}: {name}: {description}\n'
            for p, name, description in normalArray
        )
        result = result.rstrip()
        set_values_for_key(key='ANDROIDNORMALPERMISSIONTITLE', zh='一般权限信息', en='Normal Permission information')
        set_values_for_key(key='ANDROIDNORMALPERMISSIONINFO', zh='应用获取的一般权限信息',
                           en='Application\'s normal permission information')
        Info(title=get_value('ANDROIDNORMALPERMISSIONTITLE'), level=0, info=get_value('ANDROIDNORMALPERMISSIONINFO'),
             result=result).description()

    if len(dangerousArray) > 0:
        result = ''.join(
            f'{p}: {name}: {description}\n'
            for p, name, description in dangerousArray
        )
        result = result.rstrip()
        set_values_for_key(key='ANDROIDDANGEROUSPERMISSIONTITLE', zh='危险权限信息',
                           en='Dangerous Permission information')
        set_values_for_key(key='ANDROIDDANGEROUSPERMISSIONINFO', zh='应用获取的危险权限信息',
                           en='Application\'s dangerous permission information')
        Info(title=get_value('ANDROIDDANGEROUSPERMISSIONTITLE'), level=3,
             info=get_value('ANDROIDDANGEROUSPERMISSIONINFO'),
             result=result).description()

    if len(coreArray) > 0:
        result = ''.join(
            f'{p}: {name}: {description}\n'
            for p, name, description in coreArray
        )
        result = result.rstrip()
        set_values_for_key(key='ANDROIDCOREPERMISSIONTITLE', zh='核心权限信息', en='Core Permission information')
        set_values_for_key(key='ANDROIDCOREPERMISSIONINFO', zh='应用获取的核心权限信息',
                           en='Application\'s core permission information')
        Info(title=get_value('ANDROIDCOREPERMISSIONTITLE'), level=2, info=get_value('ANDROIDCOREPERMISSIONINFO'),
             result=result).description()

    if len(specialArray) > 0:
        result = ''.join(
            f'{p}: {name}: {description}\n'
            for p, name, description in specialArray
        )
        result = result.rstrip()
        set_values_for_key(key='ANDROIDSPECIALPERMISSIONTITLE', zh='特殊权限信息', en='Special Permission information')
        set_values_for_key(key='ANDROIDSPECIALPERMISSIONINFO', zh='应用获取的特殊权限信息',
                           en='Application\'s special permission information')
        Info(title=get_value('ANDROIDSPECIALPERMISSIONTITLE'), level=1, info=get_value('ANDROIDSPECIALPERMISSIONINFO'),
             result=result).description()

    if len(newPermissionList) > 0:
        result = ''.join(f'{p}\n' for p in newPermissionList)
        result = result.rstrip()
        set_values_for_key(key='ANDROIDPERMISSIONTITLE', zh='其他权限信息', en='Other Permission information')
        set_values_for_key(key='ANDROIDPERMISSIONINFO', zh='应用获取的其他权限信息',
                           en='Application\'s other permission information')
        Info(title=get_value('ANDROIDPERMISSIONTITLE'), level=0, info=get_value('ANDROIDPERMISSIONINFO'),
             result=result).description()

    results = []
    # 从 Android 中检索以下内容，查询是否导出
    # activity-alias: 
        # Activity Alias是Activity的别名，它允许在应用程序中使用不同的名称来引用同一个Activity。
        # Activity Alias可以用于创建应用程序的快捷方式或在不同的应用程序之间共享Activity。
    # activity:
        # Activity是Android应用程序的一个基本组件，用于提供用户界面。
        # 每个Activity都代表应用程序中的一个屏幕，用户可以与之进行交互。
    # service:
        # Service是在后台运行的组件，用于执行长时间运行的任务或在后台处理某些操作。
        # Service可以在应用程序的生命周期之外运行，并且可以与其他组件进行通信。
    # reveiver:
        # 用于接收和响应系统广播消息的组件。
        # 广播消息可以来自系统、其他应用程序或应用程序内部的组件。
        # 可以用于执行特定的操作或触发其他组件的操作。
    # provider:
        # 用于在Android应用程序之间共享数据。它提供了一种标准化的接口，
        # 允许其他应用程序访问和操作应用程序中的数据。
        # Content Provider可以用于存储和检索数据，例如联系人列表、媒体文件等。
    exportedList = root.getElementsByTagName('activity-alias') + root.getElementsByTagName(
        'activity') + root.getElementsByTagName('service') + root.getElementsByTagName(
        'receiver') + root.getElementsByTagName('provider')
    for a in exportedList:
        # 组件的exported属性用于指定组件是否可以被其他应用程序或系统访问。
        # 当exported属性设置为true时，表示该组件是公开的，可以被其他应用程序或系统调用和访问。
        # 这意味着其他应用程序可以通过Intent启动该组件，或者使用Content Provider访问该组件提供的数据。
        # 但是，需要注意的是，将组件的exported属性设置为true可能存在安全风险。
        # 如果一个组件没有进行适当的安全性考虑，其他应用程序可能会滥用该组件，导致潜在的安全漏洞。
        # 因此，在设计应用程序时，应仔细考虑组件的exported属性，并确保只有必要的组件被公开。
        if a.getAttribute('android:exported') == 'true':
            p = a.getAttribute('android:name')
            results.append(p)

    set_values_for_key(key='ANDROIDEXPORTEDTITLE', zh='组件导出检测', en='Component export detection')
    set_values_for_key(key='ANDROIDEXPORTEDINFO', zh='检测导出的组件信息', en='Detect exported component information')
    Info(title=get_value('ANDROIDEXPORTEDTITLE'), level=0, info=get_value('ANDROIDEXPORTEDINFO'),
         result="\n".join(results)).description()


def apkInfo(filePath):
    set_values_for_key(key='ANDROIDSDKVERSION', zh='\n  SDK版本: ', en='\n  SDK Version: ')
    set_values_for_key(key='ANDROIDVERSION', zh='\n  版本号: ', en='\n  Version: ')
    set_values_for_key(key='ANDROIDVERSIONNAME', zh='\n  版本名: ', en='\n  Version name: ')
    # apktool.yml 文件是 apktool 工具解压 apk 后的结果文件之一，包含 apk 部分基本信息     
    yml = f'{filePath}/apktool.yml'
    result = ''
    with open(yml, mode='r') as f:
        io = f.read()
        strArr = str(io).split('\n')
        for s in strArr:
            if 'minSdkVersion' in s:
                result += '  minSdkVersion: ' + s.split(':')[-1].lstrip().replace("'", '')
            if 'targetSdkVersion' in s:
                result += get_value('ANDROIDSDKVERSION') + s.split(':')[-1].lstrip().replace("'", '')
            if 'versionCode' in s:
                result += get_value('ANDROIDVERSION') + s.split(':')[-1].lstrip().replace("'", '')
            if 'versionName' in s:
                result += get_value('ANDROIDVERSIONNAME') + s.split(':')[-1].lstrip().replace("'", '')

    set_values_for_key(key='ANDROIDINFOTITLE', zh='应用基本信息', en='Basic application information')
    set_values_for_key(key='ANDROIDINFOINFO', zh='App的基本信息', en='Basic information of the app')
    Info(title=get_value('ANDROIDINFOTITLE'), level=0, info=get_value('ANDROIDINFOINFO'), result=result).description()


def apkPermissionList(root):
    # 提取 AndroidManifest.xml 文件中 uses-permission 字段与 permission 字段
    # <uses-permission>标签用于声明应用程序需要访问的权限。
        # 这些权限可能涉及到设备功能、敏感数据或其他应用程序的操作等。
    # <permission>标签用于声明自定义权限，即应用程序自定义的权限。
    ps = root.getElementsByTagName('uses-permission')
    permissionList = {p.getAttribute('android:name') for p in ps}
    ps = root.getElementsByTagName('permission')
    for p in ps:
        permissionList.add(p.getAttribute('android:name'))
    return permissionList


def apkPermissionLevel(permissionList):
    normal = {
        '访问额外位置 (ACCESS_LOCATION_EXTRA_COMMANDS)': '允许应用软件访问额外的位置提供指令',
        '获取网络连接(ACCESS_NETWORK_STATE)': '允许获取网络连接信息',
        '设置通知(ACCESS_NOTIFICATION_POLICY)': '允许设置通知策略',
        '蓝牙(BLUETOOTH)': '允许应用软件连接配对过的蓝牙设备',
        '管理蓝牙(BLUETOOTH_ADMIN)': '允许应用软件管理蓝牙，搜索和配对新的蓝牙设备',
        '发送持久广播(BROADCAST_STICKY)': '允许应用发送持久广播',
        '更改网络连接状态(CHANGE_NETWORK_STATE)': '允许应用更改网络连接状态，自动切换网络',
        '改变WIFI多播模式 (CHANGE_WIFI_MULTICAST_STATE)': '允许应用进入WIFI多播模式，允许应用使多播地址接收发送到无线 网络上所有设备(而不仅是用户手机)数据包。',
        '更改WIFI连接状态(CHANGE_WIFI_STATE)': '允许应用改变WIFI连接状态',
        '禁用锁屏(DISABLE_KEYGUARD)': '允许应用禁用系统锁屏。允许应用停用键锁以及任何关联的密码安 全措施。例如让手机在接听来电时停用键锁，在通话结束后重新启用键锁。',
        '展开或折叠状态栏(EXPAND_STATUS_BAR)': '允许应用展开和折叠状态栏',
        '前台服务(FOREGROUND_SERVICE)': '允许应用使用前台服务',
        '获取包大小(GET_PACKAGE_SIZE)': '允许应用获取安装包占空间大小',
        '安装桌面快捷方式(INSTALL_SHORTCUT)': '允许应用在桌面安装快捷方式',
        '使用互联网(INTERNET)': '允许应用打开网络接口',
        '后台杀进程(KILL_BACKGROUND_PROCESSES)': '允许应用调用特定方法结束其他应用的后台进程',
        '管理自身通话(MANAGE_OWN_CALLS)': '允许拥有通话功能的应用通过自身连接管理服务接口处理自身的 通话行为',
        '修改音频设置(MODIFY_AUDIO_SETTINGS)': '允许该应用修改移动智能终端音频设置',
        '使用NFC(NFC)': '允许应用使用NFC进行I/O操作，与其他NFC标签、卡和读卡器通信',
        '读取帐户同步设置(READ_SYNC_SETTINGS)': '允许该应用读取某个帐户的同步设置。例如，此权限可确定“联系 人”是否与允许该应用读取某个帐户的同步设置',
        '读取帐户同步统计信息(READ_SYNC_STATS)': '允许该应用读取某个帐户的同步统计信息，包括活动历史记录和数据量',
        '接收启动完成广播(RECEIVE_BOOT_COMPLETED)': '允许应用接收系统启动完成广播',
        '重新排序正在运行的应用(REORDER_TASKS)': '允许应用对正在运行的应用重新排序',
        '请求后台运行(REQUEST_COMPANION_RUN_IN_BACKGROUND)': '允许应用在后台运行',
        '请求后台使用数据(REQUEST_COMPANION_USE_DATA_IN_BACKGROUND )': '允许应用在后台使用数据',
        '请求卸载应用(REQUEST_DELETE_PACKAGES)': '允许应用卸载其他应用',
        '忽略电池优化策略(REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)': '允许应用忽略系统电池优化策略',
        '设置闹钟(SET_ALARM)': '允许应用设置闹钟',
        '设置时区(SET_TIME_ZONE)': '允许应用设置系统时区',
        '设置壁纸(SET_WALLPAPER)': '允许应用设置系统壁纸',
        '设置壁纸提示(SET_WALLPAPER_HINTS)': '允许应用设置有关系统壁纸大小的提示',
        '使用红外线发射器(TRANSMIT_IR)': '允许应用使手机的红外线发射器',
        '删除桌面快捷方式(UNINSTALL_SHORTCUT)': '允许应用删除桌面快捷方式',
        '使用指纹(USE_FINGERPRINT)': '允许应用使手机指纹设备',
        '振动(VIBRATE)': '允许应用使手机振动',
        '唤醒锁(WAKE_LOCK)': '允许应用持有系统唤醒锁，防止进程进入睡眠状态或息屏',
        '修改帐户同步设置(WRITE_SYNC_SETTINGS)': '允许该应用修改某个帐户的同步设置，包括启用和停用同步',
        '读取应用列表(QUERY_ALL_PACKAGES)': '允许应用读取手机上的应用列表，仅适用于target sdk大于等于30以上的Android设备和应用软件'
    }
    dangerous = {
        '读取日历(READ_CALENDAR)': '读取日历内容',
        '写入或删除日历(WRITE_CALENDAR)': '修改日历内容',
        '读取手机识别码(READ_PHONE_STATE)': '允许应用软件读取电话状态',
        '读取联系人(READ_CONTACTS)': '允许应用软件读取联系人通讯录信息',
        '写入或删除联系人(WRITE_CONTACTS)': '允许应用软件写入联系人，但不可读取',
        '访问手机账户列表(GET_ACCOUNTS)': '允许应用软件访问当前手机的账户列表信息',
        '读取传感器(BODY_SENSORS)': '允许应用软件访问用户用来衡量身体内发生的情况的传感器的数据，例如心率',
        '发送短信(SEND_SMS)': '允许应用软件发送短信',
        '接收短信(RECEIVE_SMS)': '允许应用软件接收短信 ',
        '读取短信(READ_SMS)': '允许应用软件读取短信内容 ',
        '接收WAP PUSH(RECEIVE_WAP_PUSH)': '允许应用软件接收WAP PUSH信息 ',
        '接收彩信(RECEIVE_MMS)': '允许应用软件接收彩信 ',
        '读取外部存储空间(READ_EXTERNAL_STORAGE)': '允许应用软件读取扩展存 ',
        '写入外部存储空间(WRITE_EXTERNAL_STORAGE)': '允许应用软件写入外部存储，如SD卡上写文件 ',
        '获取无线状态(ACCESS_WIFI_STATE)': '允许获取无线网络相关信息',
        '读取电话号码(READ_PHONE_NUMBERS)': '允许该应用访问设备上的电话号码',
        '读取小区广播消息(READ_CELL_BROADCASTS)': '允许应用读取您的设备收到的小区广播消息。小区广播消息是在某些地区发送的、用于发布紧急情况警告的提醒信息。恶意应用可能会在您收到小区紧急广播时干扰您设备的性能或操作',
        '从您的媒体收藏中读取位置信息(ACCESS_MEDIA_LOCATION)': '允许该应用从您的媒体收藏中读取位置信息',
        '接听来电(ANSWER_PHONE_CALLS)': '允许该应用接听来电',
        '继续进行来自其他应用的通话(ACCEPT_HANDOVER)': '允许该应用继续进行在其他应用中发起的通话',
        '身体活动(ACTIVITY_RECOGNITION)': '获取您的身体活动数据'
    }
    core = {
        '使用摄像头(CAMERA)': '允许应用软件调用设备的摄像头进行拍摄、录像',
        '访问精确位置(ACCESS_FINE_LOCATION)': '允许应用软件通过GPS获取精确的位置信息 ',
        '访问大致位置(ACCESS_COARSE_LOCATION)': '允许应用软件通过WiFi或移动基站获取粗略的位置信息',
        '在后台使用位置信息(ACCESS_BACKGROUND_LOCATION)': '即使未在前台使用此应用，此应用也可以随时访问位置信息',
        '录音或通话录音(RECORD_AUDIO)': '允许应用获取麦克风输入数据信息 ',
        '使用SIP(USE_SIP)': '允许应用软件使用SIP视频服务 ',
        '拨打电话(CALL_PHONE)': '允许应用软件拨打电话,从非系统拨号器里初始化一个电话拨号',
        '读取通话记录(READ_CALL_LOG)': '允许应用软件读取通话记录',
        '写入通话记录(WRITE_CALL_LOG)': '允许应用软件写入通话记录',
        '使用语音邮件(ADD_VOICEMAIL)': '允许应用软件使用语音邮件',
        '修改外拨电话(PROCESS_OUTGOING_CALLS)': '允许应用软件监视、修改外拨电话'
    }
    sepical = {
        '设备管理器(BIND_DEVICE_ADMIN)': '激活使用设备管理器',
        '辅助模式(BIND_ACCESSIBILITY_SERVICE)': '使用无障碍功能',
        '读写系统设置(WRITE_SETTINGS)': '允许应用读取或写入系统设置',
        '读取应用通知(BIND_NOTIFICATION_LISTENER_SERVICE)': '允许应用读取应用的通知内容',
        '悬浮窗(SYSTEM_ALERT_WINDOW)': '允许应用显示在其他应用之上，或后台弹出界面 ',
        '读取应用使用情况(PACKAGE_USAGE_STATS)': '允许应用读取本机的应用使用情况 ',
        '请求安装应用(REQUEST_INSTALL_PACKAGES)': '允许应用安装其他应用 ',
        '访问所有文件(MANAGE_EXTERNAL_STORAGE)': '允许应用访问分区存储模式下SD卡上的所有文件',
        '应用软件列表(GET_INSTALLED_APPS)': '允许应用读取手机上的应用软件列表'
    }
    normalArray = []
    dangerousArray = []
    coreArray = []
    specialArray = []
    # copy()方法用于创建一个列表的副本。
    # 通过将原始列表作为参数传递给copy()方法，可以创建一个新的列表，
    # 其中包含与原始列表相同的元素。
    newPermissionList = permissionList.copy()
    for p in permissionList:
        # 实现逻辑：
            # 1.判断从 AndroidManifest.xml 文件中检索出的权限项目是否存在于预定义的各类 permission 字典中
            # 2.如果存在，则记入对应类型的列表中，例如
                # ('android.permission.DISABLE_KEYGUARD', '禁用锁屏', '允许应用禁用系统锁屏。允许应用停用键锁以及任何关联的密码安 全措施。例如让手机在接听来电时停用键锁，在通话结束后重新启用键锁。')
                # ('android.permission.FOREGROUND_SERVICE', '前台服务', '允许应用使用前台服务')
                # ('android.permission.CHANGE_WIFI_STATE', '更改WIFI连接状态', '允许应用改变WIFI连接状态')
                # ...
            # 3.将未与上述各字典匹配的权限内容记录为 newPermissionList
        for key in normal:
            names = key.split('(')
            # 处理示例
                # p:'com.oppo.launcher.permission.WRITE_SETTINGS'
                # key:'访问额外位置 (ACCESS_LOCATION_EXTRA_COMMANDS)'
                # names:['访问额外位置 ', 'ACCESS_LOCATION_EXTRA_COMMANDS)']
                # names[-1].strip().replace(')', ''): ACCESS_LOCATION_EXTRA_COMMANDS
                # p.split('.')[-1]: WRITE_SETTINGS
            if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                normalArray.append((p, names[0], normal[key]))
                newPermissionList.remove(p)
                break
        for key in dangerous:
            names = key.split('(')
            if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                dangerousArray.append((p, names[0], dangerous[key]))
                newPermissionList.remove(p)
                break
        for key in core:
            names = key.split('(')
            if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                coreArray.append((p, names[0], core[key]))
                newPermissionList.remove(p)
                break
        for key in sepical:
            names = key.split('(')
            if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                specialArray.append((p, names[0], sepical[key]))
                newPermissionList.remove(p)
                break
    return normalArray, dangerousArray, coreArray, specialArray, newPermissionList
