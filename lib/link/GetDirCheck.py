from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class GetDirCheck(Base):
    def scan(self):
        set_values_for_key(key='GETDIRCHECKTITLE', zh='GETDIRCHECK加密检测',
                           en='SQL Ciphe check')
        set_values_for_key(key='GETDIRCHECKINFO', zh='GETDIRCHECK加密检测',
                           en="Detect whether there are usage conditions for SQL Cipher")

        TITLE = get_value('GETDIRCHECKTITLE')
        LEVEL = 2
        INFO = get_value('GETDIRCHECKINFO')

        strline = cmdString(
            f'grep -wr "getDir" {self.appPath}'
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
                    if 'Landroid/content/Context;->getDir' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        # 提取参数 p0, v4, v3
                        v = line[start:end].split(',')[-1]
                        for j in range(i,count):
                            ll = lines[j]
                            # 除 0x0 外都是危险模式
                            if v in ll and ('0x1' in ll and '0x2' in ll and '0x3' in ll):
                                result = name + ':' + str(count - i)
                                if result not in results:
                                    results.append(result)
                                break
                                
        if len(results) > 0:
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()
        else:
            Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='safe').description()

register(GetDirCheck)