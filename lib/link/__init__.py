import os
import importlib
import logging

# 语法用于相对导入。在这里，from ..表示从当前模块所在的目录的上级目录开始导入。
from .. import ROOT_PATH, name

logger = logging.getLogger(__name__)

for item in os.listdir(os.path.join(ROOT_PATH, "link")):
    if '__' in item or '.DS_Store' in item:
        continue
    else:
        prefix, suffix = os.path.splitext(item)
        print(prefix,suffix)
        if suffix == ".py":
            try:
                importlib.import_module(f"{name}.link.{prefix}")
            except Exception as e:
                logger.exception(e)