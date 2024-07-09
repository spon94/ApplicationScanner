#!/usr/bin/python3
# -*- coding:utf-8 -*-
from rich.table import Table

from lib.tools import *
from lib.translation import *


class Info:
    def __init__(self, key='Info', title='', level=0, info='', result=''):
        set_values_for_key(key='LEVELINFO', zh='信息', en='Info')
        set_values_for_key(key='LEVELLOW', zh='低危', en='Low')
        set_values_for_key(key='LEVELMIDDLE', zh='中危', en='Middle')
        set_values_for_key(key='LEVELHIGH', zh='高危', en='High')
        set_values_for_key(key='LEVELURGENT', zh='紧急: ', en='Urgent')
        set_values_for_key(key='TESTITEMS', zh='检测项目', en='Test case')
        set_values_for_key(key='CASEDESC', zh='项目描述', en='Case description')
        set_values_for_key(key='LEVELDANGER', zh='危险等级', en='Levels of danger')
        set_values_for_key(key='PROJECTDESC', zh='项目描述', en='Project description')
        self.title = title
        self.level = level
        self.info = info
        self.result = result
        self.key = key

    def description(self):
        level = {
            0: get_value('LEVELINFO'),
            1: get_value('LEVELLOW'),
            2: get_value('LEVELMIDDLE'),
            3: get_value('LEVELHIGH'),
            4: get_value('LEVELURGENT')
        }
        if len(self.result) > 0:
            levelColor = 'white'
            if self.level == 1:
                levelColor = 'cyan'
            elif self.level == 2:
                levelColor = 'magenta'
            elif self.level in [3, 4]:
                levelColor = 'red'
            # 绘制表
            # show_header: 表格标题行
            # show_lines: 表格分隔线
            table = Table(show_header=False, show_lines=True)
            # 向表格中添加列，内容左对齐
            table.add_column("Title", justify="left")
            table.add_column("Result", justify="left")
            # 表格中添加行，支持更改文字格式
            table.add_row(get_value('TESTITEMS'), f'[bold green]{self.title}[/bold green]')
            table.add_row(get_value('CASEDESC'), f'[bold yellow]{self.info}[/bold yellow]')
            table.add_row(
                get_value('LEVELDANGER'),
                f'[bold {levelColor}]{level[self.level]}[/bold {levelColor}]',
            )
            table.add_row(get_value('PROJECTDESC'), f'[bold]{self.result}[/bold]')
            # 在终端中打印表格
            console.print(table)
