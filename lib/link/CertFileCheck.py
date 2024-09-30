from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class CertFileCheck(Base):
    def scan(self):
        set_values_for_key(key='CERTFILETITLE', zh='CERTFILE加密检测',
                           en='SQL Cipherion detection')
        set_values_for_key(key='SQLCHECHINFO', zh='检测App是否存在明文存储的证书文件',
                           en="Detect whether there are usage conditions for SQL Cipherion in the App")

        TITLE = get_value('CERTFILETITLE')
        LEVEL = 2
        INFO = get_value('SQLCHECHINFO')

        cert_files = []

        for root, _, files in os.walk(self.appPath):
            for file in files:
                # 通过证书文件后缀查找文件
                if file.endswith(('.RSA', '.DSA', '.EC', '.SF', '.MF', '.crt', '.CER')):
                    cert_files.append(os.path.join(root, file))
        if len(cert_files) > 0:
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(cert_files)).description()
        else:
            # comment: 
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='safe').description()


register(CertFileCheck)
