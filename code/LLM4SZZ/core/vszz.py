import os
import sys
import logging as log
import traceback
from typing import List, Set
import subprocess
import json

from git import Commit

from core.abstract_szz import AbstractSZZ, ImpactedFile

from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
import Levenshtein


def remove_whitespace(line_str):
    return ''.join(line_str.strip().split())

def compute_line_ratio(line_str1, line_str2):
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)

MAXSIZE = sys.maxsize

class MySZZ(AbstractSZZ):
    """
    My SZZ implementation.

    Supported **kwargs:

    * ignore_revs_file_path

    """

    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None, use_temp_dir: bool = False):
        super().__init__(repo_full_name, repo_url, repos_dir, use_temp_dir)
        # self.ast_map_path = ast_map_path

    def find_bic(self, fix_commit_hash: str, impacted_files: dict) -> Set[Commit]:
        """
        Find bug introducing commits candidates.

        :param str fix_commit_hash: hash of fix commit to scan for buggy commits
        :param List[ImpactedFile] impacted_files: list of impacted files in fix commit
        :key ignore_revs_file_path (str): specify ignore revs file for git blame to ignore specific commits.
        :returns Set[Commit] a set of bug introducing commits candidates, represented by Commit object
        """
        
        # log.info(f"find_bic() kwargs: {kwargs}")

        # ignore_revs_file_path = kwargs.get('ignore_revs_file_path', None)
        # self._set_working_tree_to_commit(fix_commit_hash)

        bug_introd_commits = []
        for imp_file, func_data in impacted_files.items():
            source_file = imp_file
            for func_name, blame_lines in func_data.items():
                # for lineno in blame_lines:

                try:
                    blame_data = self._blame(
                        # rev='HEAD^',
                        rev='{commit_id}^'.format(commit_id=fix_commit_hash),
                        file_path=source_file,
                        modified_lines=blame_lines,
                        # ignore_revs_file_path=ignore_revs_file_path,
                        ignore_whitespaces=False,
                        skip_comments=True
                    )

                    for entry in blame_data:
                        if entry.file_path!=imp_file:
                            imp_file = entry.file_path
                        print(entry.commit, entry.line_num, entry.line_str)
                        previous_commits = []
                        
                        blame_result = entry
                        while True:
                            mapped_line_num = self.map_modified_line(blame_result, imp_file)
                            previous_commits.append((blame_result.commit.hexsha, blame_result.line_num, blame_result.line_str))
                            
                            if mapped_line_num == -1:
                                break
                            
                            
                            blame_data2 = self._blame(
                                            rev='{commit_id}^'.format(commit_id=blame_result.commit.hexsha),
                                            file_path=imp_file,
                                            modified_lines=[mapped_line_num],
                                            # ignore_revs_file_path=ignore_revs_file_path,
                                            ignore_whitespaces=False,
                                            skip_comments=True
                                        )
                            blame_result = list(blame_data2)[0]
                            # print(blame_result.commit.hexsha, blame_result.line_num)
                            # print(mapped_line_num, blame_result.commit.hexsha, blame_result.line_num, blame_result.line_str)
                            # previous_commits.append((blame_result.commit, blame_result.line_num, blame_result.line_str))

                        # bug_introd_commits[entry.line_num] = {'line_str': entry.line_str, 'file_path': entry.file_path, 'previous_commits': previous_commits}
                        bug_introd_commits.append({'line_num':entry.line_num, 'func_name':func_name, 'line_str': entry.line_str, 'file_path': entry.file_path, 'previous_commits': previous_commits})
                        # bug_introd_commits.append(previous_commits)
                except:
                    print(traceback.format_exc())

        return bug_introd_commits

    
       

    def map_modified_line(self, blame_entry, blame_file_path):
        #TODO: rename type 
        blame_commit = PyDrillerGitRepo(self.repository_path).get_commit(blame_entry.commit.hexsha)
        # print('get blame commit', blame_commit, blame_entry.commit.hexsha)

        for mod in blame_commit.modifications:
            file_path = mod.new_path
            if mod.change_type == ModificationType.DELETE or mod.change_type == ModificationType.RENAME:
                file_path = mod.old_path

            if file_path != blame_file_path:
                continue

            if not mod.old_path:
                # "newly added"
                return -1

            lines_added = [added for added in mod.diff_parsed['added']]
            lines_deleted = [deleted for deleted in mod.diff_parsed['deleted']]

            if len(lines_deleted) == 0:
                return -1
            
            print('line added/deleted', len(lines_added), len(lines_deleted))

            if blame_entry.line_str:
                sorted_lines_deleted = [(line[0], line[1], 
                                            compute_line_ratio(blame_entry.line_str, line[1]), 
                                            abs(blame_entry.line_num - line[0])) 
                                        for line in lines_deleted]
                sorted_lines_deleted = sorted(sorted_lines_deleted, key=lambda x : (x[2], MAXSIZE-x[3]), reverse=True)
                # print(sorted_lines_deleted)
                
                # print(sorted_lines_deleted)
                if sorted_lines_deleted[0][2] > 0.75:
                    return sorted_lines_deleted[0][0]
                                             
        return -1        
                
                    