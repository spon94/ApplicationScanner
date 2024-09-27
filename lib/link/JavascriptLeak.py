from lib.translation import *
from lib.tools import *

from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
from pathlib import Path

apksigner = str(Path(__file__).parents[2] / 'ThirdTools/apksigner.jar')


class JavascriptLeak(Base):
    def scan(self):
        arr = RunCMD(f'find \'{self.appPath}\' -type f -name \'*.js\' | cut -d \'/\' -f6-').execute()[0].decode('utf-8',
                                                                                                      'replace').split(
        '\n')
        result = ''.join(line + '\n' for line in arr)
        if result != "":
            result.rstrip()

            set_values_for_key(key='JSLEAKTITLE', zh='Javascript 文件泄露', en='Javascript leak')
            set_values_for_key(key='JSLEAKINFO', zh='如果js文件被读取可能造成功能逻辑泄露，如果被篡改，可能被植入钓鱼页面或者恶意代码，造成用户的敏感信息泄露。', en='Javascript leak')
            
            Info(title=get_value('JSLEAKTITLE'), level=1, info=get_value('JSLEAKINFO'),
                result=result).description()

register(JavascriptLeak)
