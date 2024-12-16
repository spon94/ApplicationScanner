from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class PhoneNumberCheck(Base):
    def scan(self):
        set_values_for_key(key='ANDROIDPHONENUMBERCHECKTITLE', zh='PHONENUMBER泄露检测',
                           en='PHONENUMBER leak detection')
        set_values_for_key(key='ANDROIDPHONENUMBERCHECHINFO', zh='检测App泄露的PHONENUMBER',
                           en="Detect PHONENUMBER leaked by App")

        TITLE = get_value('ANDROIDPHONENUMBERCHECKTITLE')
        LEVEL = 1
        INFO = get_value('ANDROIDPHONENUMBERCHECHINFO')

        strline = cmdString('grep -r -Eo \'\b1[3-9]\d{9}\b\' ' + self.appPath)
        out = os.popen(strline).readlines()
        results = []
        for item in out:
            if 'Binary file' in item or 'schemas.android.com' in item or 'android.googlesource.com' in item:
                continue
            results.append(item)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(PhoneNumberCheck)
