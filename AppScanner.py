#!/usr/bin/python3
# -*- coding:utf-8 -*-
# 使用 python 的 getopt 模块解析命令行参数
import getopt
import sys

from lib import translation
from lib.apk import apkScan
from lib.ipa import ipaScan
from lib.sdk import *

Version = 2.4

console.print('''
                      _____                                 
    /\               / ____|                                
   /  \   _ __  _ __| (___   ___ __ _ _ __  _ __   ___ _ __ 
  / /\ \ | '_ \| '_ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 / ____ \| |_) | |_) |___) | (_| (_| | | | | | | |  __/ |   
/_/    \_\ .__/| .__/_____/ \___\__,_|_| |_|_| |_|\___|_|   
         | |   | |                                          
         |_|   |_|                                          
''', style='blink bold green')

console.print(
    f'                             [italic green]ParadiseDuo[/italic green]  [{Version}]'
)


def printUse():
    console.print('''
    Usage:      
        python3 AppScanner.py -i *.apk/*.ipa/*.aab
    
        -h help
        -i <inputPath>
        -s save cache (Default clear cache)
        -l language ['zh', 'en'] (Default zh)
        -f <CheckList Path>
    ''', style='green')


translation.init()
translation.changeLanguage('zh')


def main(argv):
    inputfile = ''
    checklist = ''
    # 使用getopt.getopt()函数来执行解析操作。
    # 该函数接受三个参数：argv表示命令行参数列表，
    # "hsi:l:f:"表示短选项的字符串，
    # ["inputPath=language=checklist="]表示长选项的列表。
    try:
        # opts是一个包含选项和对应值的列表，
        # args是一个包含不属于任何选项的参数的列表，即用于存放各选项的参数。
        opts, args = getopt.getopt(argv, "hsi:l:f:", ["inputPath=language=checklist="])
    # 过程中发生错误（比如无效的选项或缺少参数），
    # 则会抛出getopt.GetoptError异常。
    except getopt.GetoptError:
        printUse()
        # sys.exit()是Python标准库sys模块中的一个函数，用于退出程序的执行。
        # 接受一个可选的参数作为退出状态码，用于指示程序的退出状态。
        # 语法：sys.exit([arg])
        # 参数：arg是一个可选的整数参数，表示程序的退出状态码。默认值为0。
        # 返回值：sys.exit()函数不返回任何值。它会终止当前的程序执行，并返回给操作系统一个退出状态码。
        sys.exit(2)

    save = False
    # 根据 printuse() 中的选项帮助信息，匹配各选项参数。
    for (opt, arg) in opts:
        if opt == '-h':
            printUse()
            sys.exit()
        elif opt in ("-i", "--inputPath"):
            inputfile = arg
        elif opt in ("-l", "--language"):
            translation.changeLanguage(arg)
        elif opt in ("-f", "--checklist"):
            checklist = arg
        elif opt == '-s':
            save = True
    
    # 解析输入文件信息
    # 1.判断是否存在
    # 2.通过文件后缀名进行匹配，并调用对应的函数
    if len(inputfile) > 0:
        if not os.path.exists(inputfile):
            console.print('File not exist!', style='red bold')
            sys.exit(0)
        if inputfile.endswith('.apk') or inputfile.endswith('.aab'):
            apkScan(inputfile, save)
        elif inputfile.endswith('.ipa'):
            ipaScan(inputfile, save)
        elif inputfile.endswith('.framework'):
            checkFramework(inputfile, checklist)
        elif inputfile.endswith('.aar'):
            checkAar(inputfile, checklist)
        elif inputfile.endswith('.a'):
            checkA(inputfile, checklist)
        elif inputfile.endswith('.so'):
            checkSo(inputfile, checklist)
        elif inputfile.endswith('.jar'):
            checkJar(inputfile, checklist)
        else:
            console.print('Application must be *.apk or *.ipa', style='red bold')
            sys.exit(2)
    else:
        printUse()
        sys.exit(2)


if __name__ == '__main__':
    main(sys.argv[1:])
