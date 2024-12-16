from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class AccountPasswdCheck(Base):
    def scan(self):

        # 定义捕获日志等级
        keywords = [
            "DEFAULT_ACCOUNT",
            "CHOOSE_ACCOUNT",
            "addAccountOptions",
            "addAccountRequiredFeatures",
            "alwaysPromptForAccount",
            "selectedAccount"
        ]

        set_values_for_key(key='ACCOUNTPASSWDTITLE', zh='账户密码信息检测',
                           en='SQL injection detection')
        set_values_for_key(key='ACCOUNTPASSWDINFO', zh='检测App是否存在敏感账户密码信息',
                           en="Detect whether there are usage conditions for SQL injection in the App")

        TITLE = get_value('ACCOUNTPASSWDTITLE')
        LEVEL = 1
        INFO = get_value('ACCOUNTPASSWDINFO')

        results = []
        for word in keywords:
            strline = cmdString(
                f'grep -r "{word}" {self.appPath}'
            )
            paths = getSmalis(os.popen(strline).readlines())
            for path in paths:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    count = len(lines)
                    name  = getFileName(path)
                    for i in range(count):
                        line = lines[i]
                        for pattern in keywords:
                            if pattern in line:
                                result = name + ' : ' + str(i + 1) + line
                                if result not in results:
                                    results.append(result)

        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(AccountPasswdCheck)
