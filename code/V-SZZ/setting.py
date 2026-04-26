import sys
import os

# config your working folder and the correponding folder
WORK_DIR = '/home/xinweimao/alv_evaluate/myResearch/workspace/code/V-SZZ'

# REPOS_DIR = os.path.join(WORK_DIR, 'repo')
REPOS_DIR = '/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result'

DATA_FOLDER = os.path.join(WORK_DIR, 'data')

SZZ_FOLDER = os.path.join(WORK_DIR, 'icse2021-szz-replication-package')

DEFAULT_MAX_CHANGE_SIZE = sys.maxsize

AST_MAP_PATH = os.path.join(WORK_DIR, 'ASTMapEval_jar')

LOG_DIR = os.path.join(WORK_DIR, 'GitLogs')

TMP_DIR = os.path.join(WORK_DIR, 'tmp')

input_DIR = ''