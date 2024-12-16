from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *
import re

class HardCodingCheck(Base):
    def scan(self):
        
        # 加密 API 列表
        encryption_apis = [
            'Ljavax/crypto/Cipher;',
            'Ljavax/crypto/spec/SecretKeySpec;',
        ]

        # 字符串白名单列表 
        white_keys = [
            'CBC',
            'UTF-8',
            'AES',
            'GCM',
            'AndroidKeyStore',
            'GCMKS',
            'NoPadding',
            'PKCS5Padding',
            'RSA',
            'ECB',
            'PKCS1Padding',
            'SHA-1',
            'SHA-256',
            'SHA-512',
            'SHA1',
            'SHA256',
            'SHA512',
            'DES',
            'AGC',
            'huawei',
            'vivo',
            'MD5',
            'ByteString'
        ]

        set_values_for_key(key='HARDCODINGCHECK', zh='硬编码检测',
                           en='HardCodingCheck')
        set_values_for_key(key='HARDCODINGINFO', zh='硬编码检测',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('HARDCODINGCHECK')
        LEVEL = 1
        INFO = get_value('HARDCODINGINFO')

        results = []
        for api in encryption_apis:
            strline = cmdString(
                f'grep -ir "{api}" {self.appPath}'
            )
            paths = getSmalis(os.popen(strline).readlines())
            for path in paths:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    count = len(lines)
                    name  = getFileName(path)
                    for i in range(count):
                        line = lines[i]
                        if 'const-string' in line:
                            match = re.search(r'const-string\s+v\d+,\s+"([^ ]+)"', line)
                            if match:
                                result = name + ' : ' + line
                                if result not in results:
                                    results.append(result)
        filter_results = []
        for j in range(len(white_keys)):
            for i in range(len(results)):
                if white_keys[j] in results[i]:
                    results[i] = ''
        for result in results:
            if result != '':
                filter_results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(filter_results)).description()


register(HardCodingCheck)
