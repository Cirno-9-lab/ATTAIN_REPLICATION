import re
from time import strftime, strptime
import copy


class Line:
    def __init__(self, line, is_add, is_del, is_bg, lineno, raw_line):
        self.line = line
        self.raw_line = raw_line
        self.is_add = is_add
        self.is_del = is_del
        self.is_bg = is_bg
        self.lineno = lineno

    def __str__(self) -> str:
        return str(
            {
                "line": self.line,
                "is_add": self.is_add,
                "is_del": self.is_del,
                "is_bg": self.is_bg,
                "lineno": self.lineno,
            }
        )

    def get_line_info(self):
        return {
            "line": self.line,
            "is_add": self.is_add,
            "is_del": self.is_del,
            "is_bg": self.is_bg,
            "lineno": self.lineno,
        }


class Hunk:
    def __init__(self) -> None:
        self.lines = []

    def add_line(self, l) -> None:
        self.lines.append(l)

    def get_lines(self):
        return self.lines

    def __str__(self) -> str:
        ret = ""
        for l in self.lines:
            ret = ret + "\n" + l.raw_line
        return ret

    def to_str_without_del_lines(self) -> str:
        ret = ""
        for l in self.lines:
            if l.is_add:
                continue
            ret = ret + "\n" + l.raw_line
        return ret

    def set_patch_file_name(self, patch_file_name):
        self.patch_file_name = patch_file_name

    def get_patch_file_name(self):
        return self.patch_file_name


class File:
    def __init__(self, fname, is_add, is_del, is_mod, is_rename, file_lines):
        self.file_name = fname
        self.is_add = is_add
        self.is_del = is_del
        self.is_mod = is_mod
        self.is_rename = is_rename
        self.file_lines = file_lines
        self.hunks = []

    def add_hunk(self, h: Hunk):
        self.hunks.append(h)
        h.set_patch_file_name(self.file_name)

    def get_info(self):
        return {
            "file_name": self.file_name,
            "is_add": self.is_add,
            "is_del": self.is_del,
            "is_mod": self.is_mod,
            "is_rename": self.is_rename,
        }

    def __str__(self) -> str:
        return str(self.get_info())

    def get_hunks(self):
        return self.hunks

    def get_raw_file_str(self) -> str:
        raw_str = ""
        for raw_line in self.file_lines:
            raw_str = raw_str + raw_line + "\n"
        return raw_str


class Patch:
    def __init__(self, content: str) -> None:
        self.content = content
        self.files = []
        self.re1 = re.compile("diff(\s)+--git(\s)+a/(\S)+(\s)+b/(\S)+")
        self.re2 = re.compile("@@(\s)+-([0-9]*),?(\S)*(\s)+\+([0-9]*),?(\S)*(\s)+@@")
        self.parse()

    def parse_cid(self, line: str) -> str:
        return line.split(" ")[1]

    def parse_author_email(self, line: str):
        author = ""
        for s in line.split(" ")[1:-1]:
            author = author + " " + s
        author = author.strip()
        email = line.split(" ")[-1]
        return author, email

    def parse_time(self, line: str):
        line = line.replace(",", "")
        time_list = line.split(" ")[1:-1]
        time_line = ""
        for t in time_list:
            time_line = time_line + t + " "
        time_line = time_line.strip()
        return strptime(time_line, "%a %d %b %Y %X")

    def parse_commit_msg(self, lines: list):
        cmsg = ""
        i = 0
        for line in lines:
            i = i + 1
            if line.startswith("Subject: [PATCH]"):
                cmsg = cmsg + line[len("Subject: [PATCH]") :]
            elif line == "---":
                return cmsg.strip(), i
            else:
                cmsg = cmsg + "\n" + line

    def parse_hunk(self, lines, beg1, beg2):
        beg1 = beg1 + 1
        beg2 = beg2 + 1
        h = Hunk()
        for l in lines:
            if l.startswith("-") and not l.startswith("--- a/") and l != ("-- "):
                h.add_line(Line(l[1:], False, True, False, beg1, l))
                beg1 = beg1 + 1
            elif l.startswith("+") and not l.startswith("+++ b/"):
                h.add_line(Line(l[1:], True, False, False, beg2, l))
                beg2 = beg2 + 1
            elif l.startswith("@@"):
                h.add_line(Line(l, False, False, False, -1, l))
            else:
                h.add_line(Line(l, False, False, True, beg1, l))
                beg1 = beg1 + 1
                beg2 = beg2 + 1
        return h

    def parse_file(self, lines: list):
        raw_lines = copy.deepcopy(lines)
        is_add = False
        is_del = False
        is_mod = False
        is_rename = False

        f1 = lines[0].split(" ")[-1][2:]
        f2 = lines[0].split(" ")[-2][2:]
        lines = lines[1:]

        if lines[0].startswith("similarity index") and f1 != f2:
            is_rename = True
            return File(f2, is_add, is_del, is_mod, is_rename, raw_lines)
        elif lines[0].startswith("deleted file mode"):
            is_del = True
        elif lines[0].startswith("new file mode"):
            is_add = True
        else:
            is_mod = True

        while len(lines) > 0 and self.re2.match(lines[0]) == None:
            lines = lines[1:]

        hunk_lines = []
        hunks = []

        while len(lines) > 0 and self.re2.match(lines[0]) != None:
            l = re.findall(r"\d+", lines[0])
            beg1 = 0
            beg2 = 0
            if len(l) < 3:
                beg1 = int(l[0]) - 1
                beg2 = int(l[1]) - 1
            else:
                beg1 = int(l[0]) - 1
                beg2 = int(l[2]) - 1

            hunk_lines.append(lines[0])
            lines = lines[1:]

            while len(lines) > 0 and self.re2.match(lines[0]) == None:
                hunk_lines.append(lines[0])
                lines = lines[1:]

            hunks.append(self.parse_hunk(hunk_lines, beg1, beg2))
            hunk_lines = []
            if len(lines) == 0:
                break

        f = File(f1, is_add, is_del, is_mod, is_rename, raw_lines)
        for h in hunks:
            f.add_hunk(h)
        return f

    def parse_files(self, lines: list):
        while len(lines) > 0 and self.re1.match(lines[0]) == None:
            lines = lines[1:]

        file_lines = []
        files = []

        while len(lines) > 0 and self.re1.match(lines[0]) != None:

            file_lines.append(lines[0])
            lines = lines[1:]
            while len(lines) > 0 and self.re1.match(lines[0]) == None:
                file_lines.append(lines[0])
                lines = lines[1:]

            files.append(self.parse_file(file_lines))
            file_lines = []
            if len(lines) == 0:
                break

        return files

    def parse(self) -> None:
        lines = self.content.split("\n")

        while not lines[0].startswith("Subject: [PATCH]"):
            lines = lines[1:]

        # assert lines[0].startswith("Subject: [PATCH]")
        self.cmsg, i = self.parse_commit_msg(lines)
        lines = lines[i:]

        self.files = self.parse_files(lines)

    def get_diff(self):
        diff = ""
        lines = self.content.split("\n")
        while len(lines) > 0 and self.re1.match(lines[0]) == None:
            lines = lines[1:]

        for l in lines:
            if l != "-- ":
                diff = diff + "\n" + l

        return diff.strip()

    def get_author(self):
        return self.author

    def get_commit_id(self):
        return self.commit_id

    def get_email(self):
        return self.email

    def get_date(self):
        return strftime("%Y-%m-%d", self.cdate)

    def get_cmsg(self):
        return self.cmsg

    def get_files(self):
        return self.files


# if __name__ == "__main__":

# with open("one_file.patch", "r") as f:
#     content = f.read()
#     p = patch(content=content)
#     add_n = 0
#     del_n = 0
#     for f in p.get_files():
#         print(f.file_name)
#         for h in f.get_hunks():
#             for l in h.get_lines():
#                 if l.is_add:
#                     add_n = add_n + 1
#                 if l.is_del:
#                     del_n = del_n + 1
#                 print(l)

#     print(f"file {len(p.get_files())} changed,{del_n} deletions,{add_n} insertions")
