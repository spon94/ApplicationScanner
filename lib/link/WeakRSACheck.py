from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class WeakRSACheck(Base):
    def scan(self):
        set_values_for_key(key='WEAKRSATITLE', zh='WEAKRSA加密检测',
                           en='SQL Ciphe check')
        set_values_for_key(key='SQLCHECHINFO', zh='检测App是否使用SqlCipher对数据库进行加密',
                           en="Detect whether there are usage conditions for SQL Cipher")

        TITLE = get_value('WEAKRSATITLE')
        LEVEL = 2
        INFO = get_value('SQLCHECHINFO')

        UNSAFE_RSA_PADDING = [
            "RSA/ECB/PKCS1Padding",
            "RSA/None/PKCS1Padding",
            "RSA/ECB/NoPadding",
            "RSA/None/NoPadding"
        ]

        strline = cmdString(
            f'grep -r "RSA" {self.appPath}'
        )
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                # 倒转文件查询方向，方便定位传入相关函数的参数
                lines.reverse()
                for i in range(count):
                    line = lines[i]
                    # 检查密钥长度
                    if 'Landroid/security/KeyPairGeneratorSpec$builder;->setKeySize' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end]
                        for j in range(i,count):
                            ll = lines[j]
                            if v in ll and '0x209' in ll:
                                result = 'Danger cipher length ' + name + ':' + line.split(',')[2:]
                                if result not in results:
                                    results.append(result)
                                break
                    # 检查填充方式
                    if 'Landroid/security/KeyPairGenerator;' in line or \
                        'Ljava/security/KeyFactory;' in line or \
                        'Ljava/security/KeyStore;' in line:
                         for padding in UNSAFE_RSA_PADDING:
                            if padding in line:
                                result = 'Danger padding method ' + name + ':' + line.split(',')[2:]
                                if result not in results:
                                    results.append(result)
                                
        if len(results) > 0:
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()
        else:
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='safe').description()

register(WeakRSACheck)
