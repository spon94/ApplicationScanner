from lib.translation import *
from lib.tools import *

from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
from pathlib import Path

apksigner = str(Path(__file__).parents[2] / 'ThirdTools/apksigner.jar')


class WeakSigningAlgorithm(Base):
    def scan(self):
        arr = RunCMD(f'java -jar {apksigner} verify -v --print-certs \'{self.appBinPath}\'').execute()[0].decode('utf-8',
                                                                                                      'replace').split(
        '\n')
        result = ''.join(line + '\n' for line in arr if 'WARNING:' not in line)
        if result != "" and ('MD5' in result or 'SHA-1' in result):
            # strip(): 
                # 此函数只会删除头和尾的字符，中间的不会删除。
                # 参数为空：默认删除字符串头和尾的空白字符(包括\n，\r，\t这些)
                # 参数不接受字符串，若传入 strip("abc")，则分别对 'a' 'b' 'c' 进行处理
            # lstrip(): strip() 功能类似，但只对左边内容做处理
            # rstrip(): strip() 功能类似，但只对右边内容做处理
            result.rstrip()
            # TODO
            set_values_for_key(key='WEAKSIGNTITLE', zh='使用弱签名算法', en='Using weak signing algorithms')
            set_values_for_key(key='WEAKSIGNINFO', zh='普遍使用的SHA-1已经过时因而不再推荐使用，基于MD5的签名的支持也已在2012年初停止，建议使用更安全的签名算法，如SHA-2（其中包括SHA-256和SHA-512）。', en='MD5 and SHA-1 are too weak to use.')
            # TODO
            Info(title=get_value('WEAKSIGNTITLE'), level=1, info=get_value('WEAKSIGNINFO'),
                result=result).description()

register(WeakSigningAlgorithm)
