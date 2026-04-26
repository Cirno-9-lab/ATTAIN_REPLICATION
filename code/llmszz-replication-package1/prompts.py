summary_system_text = """
You are a programming expert. 
You will be provided with a patch used to fix a bug. 

Your task is summarize the modifications made in the patch.
Your summary should consist of two parts, modifications in each file and their relationships.
"""

# The root cause should include the file, the function and the variable that are most likely to cause the bug.
# Note that the variable should exist in the function.
# Note that the variable and the function should not be new added. You should not retrieve the variable in the line that starts with '+'.
# Note that you'd better output only one file. If you are not sure, you can at most output two files.


root_cause_summary_text = """
Based on your summary and the commit message in the patch, you need to:

1. analyze the root cause of the bug in detail. 
2. output the file name that is most likely to cause the bug. 



Provide a response strictly in the following format:
Root cause:<Root cause>
file:<file name> 

"""


def get_criterion_text(cmsg, root_cause, full_code):
    return f"""

Based on the commit message, the root cause and the patch provided below, you need to:

1. explain how the bug occurs, including all code statements that are most likely to lead to the bug and why. 
2. explain how the bug is fixed, including code statements fixing the bug and why. 

You must include one or more code statements in point 1 and 2.
Code statements included in point 1 should be as brief as possible, only include the ones that are most related to the root cause and  the number of code statements may not exceed 3.


Here is the commit message:
{cmsg}

Here is the root cause:
{root_cause}

Here is the patch:
{full_code}

Provide a response strictly in the following format:

The code statements that lead to the bug are:
<text>
<text>
...
<text>
Reason:
<text>
The code statements that fix the bug are:
<text>
<text>
...
<text>
Reason:
<text>
"""


def get_determine_text(root_cause, information, code_snippet):

    return f"""

You are a programming expert.

You will be given details about a bug, including:
1. The root cause.
2. Code statements that lead to the bug and the reason for it.
3. Code statements that fix the bug and the reason for the fix.

Based on these details, your task is to determine whether the provided code snippet contains the bug.
Think step by step.
Be conservative in your assessment. If you are unsure, answer "no."

Root cause:
{root_cause}

Code statements information:
{information}


Now, determine whether the provided code snippet is buggy:
{code_snippet}

Please output the result in the following format:
Reason: <text>
Result: <yes or no>
"""


def get_stmt_determine_text(buggy_stmt, code_snippet):
    return f""" 
        
        Task: Determine if the provided code snippet contains the specified code statement.       
        If the code statement either directly appears in the code snippet or if a semantically similar code statement is present, respond with "yes." Otherwise, respond with "no."
        Notice that minor changes are allowed. However, be conservative when answering the question. If you are not sure, answer "no."

        
        Here is the code statement:
        {buggy_stmt}
        
        Here is the code snippet:
        {code_snippet}
        
        Please output the result in the following format:
        Reason: <text>
        Result: <yes or no>    
    """


def get_code_stmts_summary_text(cmsg, root_cause, patch):
    return f"""
        You will be given the root cause of a bug, the commit message and the corresponding patch.
        You need to extract all code statements that lead to the bug from the patch, based on the root cause and the commit message.

        Root cause:
        {root_cause}
        
        Commit message:
        {cmsg}  
        
        Patch:
        {patch}
        
        Provide a response strictly in the following format:
        Code statements:
        <text1>
        <text2>
        ...
        <textN>
    """


def get_code_stmts_ranking_text(root_cause, code_stmts):
    return f"""
        You are a programming expert.
        You will be given the root cause of a bug and some code statements that lead to the bug.
        Rank these code statements based on their relevance to the root cause of the bug.
        
        Root cause:
        {root_cause}
        
        code statements:
        {code_stmts}  

        Provide a response strictly in the following format:
        Ranked Code statements:
        <text1>
        <text2>
        ...
        <textN>
        ...
    """


def get_root_cause_summary_text(patch_content):
    root_cause_summary_text = f"""
        You are a programming expert. 
        You will be provided with a patch used to fix a bug. 
        Based on the commit message and modifications in the patch, you need to analyze the root cause of the bug in detail. 

        Here is the patch content:
        {patch_content}
        
        Provide a response strictly in the following format:
        Root cause:<Root cause>
    """
    return root_cause_summary_text


code_stmts_summary_text1 = f"""
    You are a programming expert.
    You will be given the root cause of a bug and  the corresponding patch.
    You need to extract the code statements that lead to the bug from  the patch, based on the root cause.

    
    Provide a response strictly in the following format:
    Code statements:
    <text1>
    <text2>
    <text3>
    <text4>
    ...
    <textN>
"""
