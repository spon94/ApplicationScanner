import os

from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info


class GifDrawableCheck(Base):
    def scan(self):
        set_values_for_key(key='GITDRAWABLECHECKTITLE', zh='Android-gif-Drawable远程代码执行漏洞',
                           en='So file cracking risk detection')
        set_values_for_key(key='GITDRAWABLECHECHINFO', zh='检测Apk中是否存在Android-gif-Drawable远程代码执行漏洞',
                           en="Detect whether the so file in Apk can be cracked and read")

        TITLE = get_value('GITDRAWABLECHECKTITLE')
        LEVEL = 2
        INFO = get_value('GITDRAWABLECHECHINFO')

        strline = f'find {self.appPath} -name *.so | grep -v "/original/"'
        arr = os.popen(strline).readlines()
        result = ''
        for item in arr:
            strline = f'readelf -S {item[:-1]}'
            out = os.popen(strline).readlines()
            if 'android-git-drawable' in out:
                filePath = '/'.join(item[:-1].split('/')[-2:])
                result += filePath + '\n'
        
        if result == '':
          result += 'Safe'
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result=result).description()

register(GifDrawableCheck)
