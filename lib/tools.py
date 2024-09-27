#!/usr/bin/python3
# -*- coding:utf-8 -*-
import os
import random
import re
import string
import subprocess

from rich.console import Console

console = Console()

# 文件白名单，如果不需要可以清空，也可以自行添加
whiteList = ['facebook', 'tencent', 'huawei', 'aliyun', 'android/support', 'xiaomi', 'vivo', 'oppo', 'airbnb', 'amap',
             'alipay', 'google', 'okhttp3', 'retrofit2', 'mozilla', 'freemarker', 'alibaba', 'qihoo', 'gson', 'jpush',
             'bugtags', 'trello', 'bumptech', 'jiguang', 'github', 'umeng', 'greenrobot', 'eclipse', 'bugly', 'sina',
             'weibo', 'j256', 'taobao/weex', 'iflytek', 'androidx/', 'meizu', 'io/agora', 'ijkplayer', 'sqlcipher',
             'cmic/sso', 'shanyan_sdk', 'svgaplayer', 'io/flutter', 'bytedance', 'kotlin', 'org/apache', 'org/aspectj',
             'baidu', 'youzan', 'jdpaysdk', 'qq', 'kotlinx', '/android/']

tasks = []


class RunCMD:
    def __init__(self, cmd):
        self.p = None
        self.cmd = cmd

    def execute(self):
        self.p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        tasks.append(self)
        return self.p.communicate()

    # @property 装饰器
    # 将方法转换为属性，使得我们可以像访问属性一样访问它们。
    @property
    def is_running(self):
        if self.p.poll() is None:
            return True
        tasks.remove(self)
        return False

    def stop(self):
        self.p.kill()
        tasks.remove(self)

    def log(self):
        return ''.join([str(item, encoding='utf-8') for item in self.p.communicate()])


def cmdString(strline):
    return f'{strline} | {grepThirdFile()}'


def randomStr(num):
    return '_' + ''.join(random.sample(string.ascii_letters + string.digits, num))


def getAPKFiles(dir):
    filesArray = []
    dirlist = os.walk(dir)
    jsFiles = []
    for root, dirs, files in dirlist:
        for file in files:
            path = os.path.join(root, file)
            if (file.endswith('.smali') or file.endswith('.so') or file.endswith('.xml') or file.endswith(
                                '.yml') or file.endswith('.html')) and '/original/' not in path:
                filesArray.append(path)
            if file.endswith('.js'):
                jsFiles.append(path)
            if file.endswith('.jsbundle') or file.endswith('.rnbundle'):
                path = changeJSBundleFile(path)
                jsFiles.append(path)
    newPaths = jsBeautify(jsFiles)
    filesArray += newPaths
    return filesArray


def getFileName(path):
    if len(path) <= 0:
        return ''
    items = str(path).split('/')
    dir = ''
    start = -1
    for i in range(len(items)):
        if 'smali' in items[i] and '.smali' not in items[i]:
            start = i
        if start not in [-1, i]:
            dir += f'{items[i]}.'
    return dir[:-1]


def jsBeautify(jsFiles):
    newFiles = []
    for file in jsFiles:
        beautifyFile = f'{file[:-3]}1.js'
        newFiles.append(beautifyFile)
        RunCMD(f"js-beautify \'{file}\' > \'{beautifyFile}\'").execute()
    while len(tasks) > 0:
        for item in tasks:
            item.is_running
    return newFiles


def changeJSBundleFile(filename):
    portion = os.path.splitext(filename)
    newName = filename
    if portion[1] in ['.jsbundle', '.rnbundle']:
        newName = f'{str(portion[0])}.js'
        os.rename(filename, newName)
    return newName


def getURL(line):
    pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    return re.findall(pattern, line[:-1])


def grepThirdFile():
    return "grep -v '" + '\|'.join(whiteList) + "'"

# 获取 grep 扫描结果的 smali 文件路径
def getSmalis(arrs):
    paths = []
    for item in arrs:
        if '.smali:' in item:
            path = item.split(':')[0]
            if path not in paths:
                paths.append(path)
    return paths


def add_escape(value):
    reserved_chars = r'''?&|!{}[]()^~*:\\"'+- '''
    replace = ['\\' + l for l in reserved_chars]
    trans = str.maketrans(dict(zip(reserved_chars, replace)))
    return value.translate(trans)
