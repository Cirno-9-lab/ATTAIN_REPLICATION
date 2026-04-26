# -*- coding: utf-8 -*-
"""
安全特征库 - 基于领域知识的候选筛选器
Security Features Library - Domain Knowledge-Based Candidate Filter

本模块定义了各类安全敏感API和模式，用于候选commit的初步筛选。
这些特征基于NVD CVE数据库中的常见漏洞模式抽象得出。
"""

from typing import List, Dict, Set

# ============================================================================
# 1. 认证与授权类 (Authentication & Authorization)
# ============================================================================
AUTH_SENSITIVE_APIS = {
    "authenticate": ["authenticate", "login", "bindAsUser", "validateCredentials", "checkPassword"],
    "session": ["getSession", "createSession", "invalidateSession", "isAuthenticated"],
    "authorization": ["hasRole", "checkPermission", "authorize", "isAuthorized"],
    "token": ["getToken", "validateToken", "verifyToken", "decodeToken"],
    "credentials": ["setCredentials", "getCredentials", "updateCredentials"]
}

AUTH_PATTERNS = [
    r"Authentication.*Provider",
    r"Login[A-Z][a-z]*",
    r"[A-Z][a-z]*Authenticator"
]

# ============================================================================
# 2. 路径遍历与文件操作 (Path Traversal & File Operations)
# ============================================================================
PATH_SENSITIVE_APIS = {
    "file_access": ["getFile", "createFile", "deleteFile", "readFile", "writeFile"],
    "path_construction": ["createRelative", "resolvePath", "canonicalPath", "normalizePath"],
    "file_io": ["FileInputStream", "FileOutputStream", "FileReader", "FileWriter"],
    "path_validation": ["isInvalidPath", "validatePath", "checkPathTraversal"]
}

PATH_PATTERNS = [
    r"\.\./",           # Parent directory traversal
    r"\.\.\\\\",        # Windows path traversal
    r"[A-Z][a-z]*Path[A-Z][a-z]*",
    r"Path[A-Z][a-z]*"
]

# ============================================================================
# 3. XML/JSON反序列化 (XML/JSON Deserialization)
# ============================================================================
DESERIALIZATION_APIS = {
    "xml": ["DocumentBuilder", "SAXParser", "XMLReader", "XMLDecoder"],
    "json": ["JSONObject", "JSONArray", "JSONParser", "readValue"],
    "object_input": ["ObjectInputStream", "readObject"],
    "yaml": ["load", "safe_load", "Yaml"]
}

DESERIALIZATION_PATTERNS = [
    r"[A-Z][a-z]*Builder[A-Z][a-z]*",
    r"[A-Z][a-z]*Parser[A-Z][a-z]*",
    r"read[A-Z][a-z]*",
    r"parse[A-Z][a-z]*"
]

# ============================================================================
# 4. SQL注入 (SQL Injection)
# ============================================================================
SQL_SENSITIVE_APIS = {
    "query": ["executeQuery", "execute", "executeUpdate", "query"],
    "statement": ["Statement", "PreparedStatement", "CallableStatement"],
    "connection": ["getConnection", "createStatement", "prepareStatement"]
}

SQL_PATTERNS = [
    r"SELECT.*FROM",
    r"INSERT.*INTO",
    r"UPDATE.*SET",
    r"DELETE.*FROM",
    r".*WHERE.*=.*\+"
]

# ============================================================================
# 5. 命令注入 (Command Injection)
# ============================================================================
COMMAND_SENSITIVE_APIS = {
    "exec": ["exec", "execute", "runtime", "process"],
    "command": ["Command", "ProcessBuilder", "Runtime\.exec"]
}

COMMAND_PATTERNS = [
    r"Runtime\.exec\(",
    r"ProcessBuilder\(",
    r"system\(",
    r"popen\(",
    r"exec[A-Z][a-z]*\("
]

# ============================================================================
# 6. 输入验证 (Input Validation)
# ============================================================================
VALIDATION_APIS = {
    "validation": ["validate", "isValid", "check", "verify", "sanitize"],
    "filtering": ["filter", "escape", "encode"],
    "normalization": ["normalize", "canonicalize", "trim"]
}

VALIDATION_PATTERNS = [
    r"validate[A-Z][a-z]*",
    r"check[A-Z][a-z]*",
    r"sanitize[A-Z][a-z]*",
    r"[A-Z][a-z]*Validator"
]

# ============================================================================
# 7. 加密与编码 (Cryptography & Encoding)
# ============================================================================
CRYPTO_SENSITIVE_APIS = {
    "encryption": ["encrypt", "decrypt", "cipher", "AES", "DES", "RSA"],
    "hash": ["hash", "md5", "sha", "digest"],
    "encoding": ["encode", "decode", "Base64", "URLEncoder"]
}

# ============================================================================
# 8. 输出编码 (Output Encoding)
# ============================================================================
OUTPUT_ENCODING_APIS = {
    "html": ["escapeHtml", "encodeForHTML", "HTMLEntityEncoder"],
    "xml": ["escapeXml", "encodeForXML"],
    "javascript": ["escapeJavaScript", "encodeForJavaScript"],
    "url": ["escapeUrl", "URLEncoder", "encodeURIComponent"]
}

# ============================================================================
# 9. 资源管理 (Resource Management)
# ============================================================================
RESOURCE_APIS = {
    "stream": ["InputStream", "OutputStream", "close", "flush"],
    "connection": ["close", "disconnect", "shutdown"],
    "memory": ["free", "release", "deallocate"]
}

# ============================================================================
# 10. 通用安全模式 (General Security Patterns)
# ============================================================================
SECURITY_PATTERNS = {
    "path_sanitization": [
        "processPath", "normalizePath", "canonicalizePath",
        "isInvalidPath", "validatePath", "sanitizePath"
    ],
    "input_filtering": [
        "filterInput", "sanitizeInput", "cleanInput",
        "escapeInput", "validateInput"
    ],
    "boundary_check": [
        "checkBounds", "validateLength", "checkRange",
        "verifySize", "validateSize"
    ],
    "null_check": [
        "checkNull", "validateNotNull", "verifyNotNull"
    ],
    "type_check": [
        "checkType", "validateType", "verifyType"
    ]
}


# ============================================================================
# 功能函数
# ============================================================================

def get_security_features_by_category(category: str) -> Dict[str, List[str]]:
    """
    根据类别获取安全特征

    Args:
        category: 特征类别 (auth, path, deserialization, sql, command, etc.)

    Returns:
        该类别的特征字典
    """
    category_map = {
        "auth": AUTH_SENSITIVE_APIS,
        "path": PATH_SENSITIVE_APIS,
        "deserialization": DESERIALIZATION_APIS,
        "sql": SQL_SENSITIVE_APIS,
        "command": COMMAND_SENSITIVE_APIS,
        "validation": VALIDATION_APIS,
        "crypto": CRYPTO_SENSITIVE_APIS,
        "output_encoding": OUTPUT_ENCODING_APIS,
        "resource": RESOURCE_APIS
    }
    return category_map.get(category, {})


def get_all_security_keywords() -> Set[str]:
    """
    获取所有安全关键词集合

    Returns:
        所有关键词的集合
    """
    keywords = set()
    for api_dict in [AUTH_SENSITIVE_APIS, PATH_SENSITIVE_APIS, DESERIALIZATION_APIS,
                     SQL_SENSITIVE_APIS, COMMAND_SENSITIVE_APIS, VALIDATION_APIS]:
        for api_list in api_dict.values():
            keywords.update(api_list)
    return keywords


def get_security_keywords() -> Dict[str, List[str]]:
    """
    获取所有安全关键词（字典格式）

    Returns:
        按类别组织的所有关键词字典
    """
    all_keywords = {}
    for category, api_dict in {
        "auth": AUTH_SENSITIVE_APIS,
        "path": PATH_SENSITIVE_APIS,
        "deserialization": DESERIALIZATION_APIS,
        "sql": SQL_SENSITIVE_APIS,
        "command": COMMAND_SENSITIVE_APIS,
        "validation": VALIDATION_APIS,
        "crypto": CRYPTO_SENSITIVE_APIS,
        "output_encoding": OUTPUT_ENCODING_APIS,
        "resource": RESOURCE_APIS
    }.items():
        all_keywords[category] = []
        for api_list in api_dict.values():
            all_keywords[category].extend(api_list)
    return all_keywords


def get_security_patterns(category: str = None) -> List[str]:
    """
    获取安全正则表达式模式

    Args:
        category: 特征类别，None返回所有模式

    Returns:
        正则表达式模式列表
    """
    all_patterns = {
        "auth": AUTH_PATTERNS,
        "path": PATH_PATTERNS,
        "deserialization": DESERIALIZATION_PATTERNS,
        "sql": SQL_PATTERNS,
        "command": COMMAND_PATTERNS,
        "validation": VALIDATION_PATTERNS
    }
    if category:
        return all_patterns.get(category, [])
    else:
        patterns = []
        for pattern_list in all_patterns.values():
            patterns.extend(pattern_list)
        return patterns


def is_security_sensitive_code(code: str, categories: List[str] = None) -> bool:
    """
    判断代码片段是否包含安全敏感内容

    Args:
        code: 代码内容
        categories: 要检查的类别列表，None表示检查所有

    Returns:
        是否包含安全敏感内容
    """
    if categories is None:
        categories = ["auth", "path", "deserialization", "sql", "command", "validation"]

    for category in categories:
        keywords = get_security_keywords() if category is None else \
                   get_security_features_by_category(category)
        for api_list in keywords.values():
            for keyword in api_list:
                if keyword.lower() in code.lower():
                    return True

        patterns = get_security_patterns(category)
        import re
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True

    return False


def get_security_score(code: str) -> float:
    """
    计算代码的安全敏感度分数

    Args:
        code: 代码内容

    Returns:
        安全分数 (0.0 - 1.0)
    """
    score = 0.0
    categories = ["auth", "path", "deserialization", "sql", "command", "validation"]
    found_categories = set()

    for category in categories:
        if is_security_sensitive_code(code, [category]):
            found_categories.add(category)

    # 基于检测到的类别数量计算分数
    score = min(len(found_categories) / len(categories), 1.0)
    return score
