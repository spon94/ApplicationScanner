from lib.translation import *
from lib.tools import *

from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
from pathlib import Path

apksigner = str(Path(__file__).parents[2] / 'ThirdTools/apksigner.jar')


class SigningJanus(Base):
    def scan(self):
        arr = RunCMD(f'java -jar {apksigner} verify -v --print-certs \'{self.appBinPath}\'').execute()[0].decode('utf-8',
                                                                                                      'replace').split(
        '\n')
        result = ''.join(line + '\n' for line in arr if 'WARNING:' not in line)
        if result != "" and ("v1 scheme (JAR signing): true" in result):
            # strip(): 
                # 此函数只会删除头和尾的字符，中间的不会删除。
                # 参数为空：默认删除字符串头和尾的空白字符(包括\n，\r，\t这些)
                # 参数不接受字符串，若传入 strip("abc")，则分别对 'a' 'b' 'c' 进行处理
            # lstrip(): strip() 功能类似，但只对左边内容做处理
            # rstrip(): strip() 功能类似，但只对右边内容做处理
            result.rstrip()
            # TODO
            set_values_for_key(key='SIGNJANUSTITLE', zh='Janus漏洞', en='Janus Expliotable')
            set_values_for_key(key='SIGNJANUSINFO', zh='Janus漏洞可以让攻击者绕过安卓系统的Signature scheme V1签名机制，用篡改过的APK覆盖原有的应用，并可访问原应用所有的数据，直接对App进行篡改', en='Signature verification details')
            # TODO
            Info(title=get_value('SIGNJANUSTITLE'), level=3, info=get_value('SIGNJANUSINFO'),
                result=result).description()

register(SigningJanus)
