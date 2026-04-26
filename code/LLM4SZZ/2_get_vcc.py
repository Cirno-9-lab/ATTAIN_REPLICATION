import os
import re
import git
from tqdm import tqdm
from io import StringIO
import json
import time
from unidiff import PatchSet
from constant import *



DATA_DIRS = ''
repos = ['FFmpeg', 'openssl', 'wireshark', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg', 'linux']


for repo in repos:
    # if repo != 'FFmpeg':
    #     continue

    start_time = time.time()
    start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

    print(f'parsing repo: {repo}')
    cmd = 'python3 gen_results_for_dels_llm.py {}'.format(repo)
    os.system(cmd)
    
    # print(f'parsing repo: {repo}')
    # cmd = 'python3 gen_results_for_no_dels_vszz.py {}'.format(repo)
    # os.system(cmd)

    end_time = time.time()
    end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    elapsed_time = end_time - start_time

    with open("./time.txt", "a") as file:
        file.write(f"step2 gen vcc: {repo}\n")
        file.write(f"repo: {repo}\n")
        file.write(f"Start time: {start_time_readable}\n")
        file.write(f"End time: {end_time_readable}\n")
        file.write(f"Step2-gen_vcc: Execution time: {elapsed_time:.2f} seconds\n")
        file.write(f"\n")

    