import ast


# Dangerous function calls we want to flag
DANGEROUS_CALLS = {
    "eval": ("Use of eval() — executes arbitrary code", "CRITICAL"),
    "exec": ("Use of exec() — executes arbitrary code", "CRITICAL"),
    "compile": ("Use of compile() — can execute arbitrary code", "HIGH"),
}

# Dangerous attribute calls like os.system, pickle.load
DANGEROUS_ATTRIBUTES = {
    ("os", "system"): ("os.system() — command injection risk", "HIGH"),
    ("subprocess", "call"): ("subprocess.call() — check for shell=True", "MEDIUM"),
    ("subprocess", "Popen"): ("subprocess.Popen() — check for shell=True", "MEDIUM"),
    ("pickle", "load"): ("pickle.load() — insecure deserialisation", "HIGH"),
    ("pickle", "loads"): ("pickle.loads() — insecure deserialisation", "HIGH"),
    ("yaml", "load"): ("yaml.load() — use safe_load() instead", "HIGH"),
}


class SecurityVisitor(ast.NodeVisitor):
    """
    Walks the AST and records dangerous patterns.
    """
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        # Case 1: direct calls like eval(...), exec(...)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in DANGEROUS_CALLS:
                message, severity = DANGEROUS_CALLS[func_name]
                self.findings.append({
                    "line": node.lineno,
                    "issue": message,
                    "severity": severity
                })

        # Case 2: attribute calls like os.system(...), pickle.load(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                method = node.func.attr
                key = (module, method)
                if key in DANGEROUS_ATTRIBUTES:
                    message, severity = DANGEROUS_ATTRIBUTES[key]
                    self.findings.append({
                        "line": node.lineno,
                        "issue": message,
                        "severity": severity
                    })

                # Special case: check for shell=True in subprocess
                if module == "subprocess":
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                            if keyword.value.value is True:
                                self.findings.append({
                                    "line": node.lineno,
                                    "issue": "subprocess with shell=True — command injection risk",
                                    "severity": "HIGH"
                                })

        # Keep walking the tree
        self.generic_visit(node)


def scan_sast(filepath: str) -> list[dict]:
    """
    Parses a Python file into an AST and flags dangerous patterns.
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except Exception as e:
        print(f"[!] Could not read {filepath}: {e}")
        return findings

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        print(f"[!] Syntax error in {filepath}: {e}")
        return findings

    visitor = SecurityVisitor()
    visitor.visit(tree)

    for finding in visitor.findings:
        finding["file"] = filepath

    return visitor.findings