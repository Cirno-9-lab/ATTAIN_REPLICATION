import os

# enter your current working directory, absolute path.
CWD = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1"
# enter your directory which saves all repos
REPOS_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result"

DATASET_DIR = os.path.join(CWD,'dataset')
SAVE_LOG_DIR = os.path.join(CWD,'save_logs')
TMP_DIR = os.path.join(CWD,'tmp_dir') 
TREE_SITTER_DIR = os.path.join(CWD,'build')


