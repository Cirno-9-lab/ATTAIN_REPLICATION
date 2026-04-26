import os
import time

#step1 get szz result

repos = ['FFmpeg', 'openssl', 'wireshark', 'linux', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg']

# for repo in repos:
#     if repo!='linux':
#         continue
#     print('step1: ' + str(repo))
#     start_time = time.time()
#     start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

#     cmd = 'python3 main.py {}'.format(repo)
#     os.system(cmd)

#     end_time = time.time()
#     end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

#     elapsed_time = end_time - start_time

#     with open("time.txt", "a") as file:
#         file.write(f"step1 get szz: {repo}\n")
#         file.write(f"repo: {repo}\n")
#         file.write(f"Start time: {start_time_readable}\n")
#         file.write(f"End time: {end_time_readable}\n")
#         file.write(f"Step1-szz: Execution time: {elapsed_time:.2f} seconds\n")
#         file.write(f"\n")


# step2 get git log info
# for repo in repos:
#     print('step2: ' + str(repo))
#     start_time = time.time()
#     start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

#     cmd = 'python3 step2_get_git_log.py {}'.format(repo)
#     os.system(cmd)

#     end_time = time.time()
#     end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

#     elapsed_time = end_time - start_time

#     with open("time.txt", "a") as file:
#         file.write(f"step2 get duplicate patch: {repo}\n")
#         file.write(f"repo: {repo}\n")
#         file.write(f"Start time: {start_time_readable}\n")
#         file.write(f"End time: {end_time_readable}\n")
#         file.write(f"Step2-gitlog: Execution time: {elapsed_time:.2f} seconds\n")
#         file.write(f"\n")

# step3 generate duplicate patch
# for repo in repos:
#     print('step3: ' + str(repo))
#     start_time = time.time()
#     start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

#     cmd = 'python3 step3.py {}'.format(repo)
#     os.system(cmd)

#     end_time = time.time()
#     end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

#     elapsed_time = end_time - start_time

#     with open("time.txt", "a") as file:
#         file.write(f"step3 get duplicate patch: {repo}\n")
#         file.write(f"repo: {repo}\n")
#         file.write(f"Start time: {start_time_readable}\n")
#         file.write(f"End time: {end_time_readable}\n")
#         file.write(f"Step3-duplicate: Execution time: {elapsed_time:.2f} seconds\n")
#         file.write(f"\n")
    # exit(0)

#step4 generate vuln versions
for repo in repos:
    print('step4: ' + str(repo))
    start_time = time.time()
    start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

    cmd = 'python3 step4_gen_vuln_version.py {}'.format(repo)
    os.system(cmd)

    end_time = time.time()
    end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    elapsed_time = end_time - start_time

    with open("time.txt", "a") as file:
        file.write(f"step4 gen vuln version: {repo}\n")
        file.write(f"repo: {repo}\n")
        file.write(f"Start time: {start_time_readable}\n")
        file.write(f"End time: {end_time_readable}\n")
        file.write(f"Step4-gen_vuln_version: Execution time: {elapsed_time:.2f} seconds\n")
        file.write(f"\n")
    