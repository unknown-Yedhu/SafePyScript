import ast
import re


class SecurityAnalyzer:
    def __init__(self, code):
        self.code = code
        self.results = []

        try:
            self.tree = ast.parse(code)
        except SyntaxError as e:
            self.tree = None
            self.results.append({
                "vulnerability": "Python Syntax Error",
                "severity": "HIGH",
                "line": e.lineno or 0,
                "description": str(e),
                "recommendation": "Fix the Python syntax error before performing security analysis."
            })

    def add_result(self, vulnerability, severity, line, description, recommendation):
        self.results.append({
            "vulnerability": vulnerability,
            "severity": severity,
            "line": line,
            "description": description,
            "recommendation": recommendation
        })

    # ---------------------------------------------------------
    # 1. Dangerous Functions
    # ---------------------------------------------------------
    def check_dangerous_functions(self):
        dangerous_functions = {
            "eval": "eval() can execute dynamically supplied Python code.",
            "exec": "exec() can execute dynamically supplied Python code."
        }

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    function_name = node.func.id

                    if function_name in dangerous_functions:
                        self.add_result(
                            f"Dangerous Function: {function_name}()",
                            "HIGH",
                            node.lineno,
                            dangerous_functions[function_name],
                            f"Avoid {function_name}() with untrusted input. Use safer alternatives."
                        )

    # ---------------------------------------------------------
    # 2. Command Injection
    # ---------------------------------------------------------
    def check_command_injection(self):
        for node in ast.walk(self.tree):

            if isinstance(node, ast.Call):

                # os.system(...)
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "system"
                ):
                    self.add_result(
                        "Command Injection: os.system()",
                        "HIGH",
                        node.lineno,
                        "os.system() executes operating system commands and can become dangerous when user input is used.",
                        "Avoid os.system() with untrusted input. Use safer subprocess APIs with controlled arguments."
                    )

                # subprocess.call(...)
                # subprocess.run(...)
                # subprocess.Popen(...)
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in ["call", "run", "Popen"]
                ):
                    self.add_result(
                        f"Potential Command Execution: subprocess.{node.func.attr}()",
                        "MEDIUM",
                        node.lineno,
                        f"subprocess.{node.func.attr}() executes operating system commands.",
                        "Use fixed command arguments and avoid passing unsanitized user input to operating system commands."
                    )

    # ---------------------------------------------------------
    # 3. SQL Injection
    # ---------------------------------------------------------
    def check_sql_injection(self):
        lines = self.code.splitlines()

        for index, line in enumerate(lines, start=1):
            lower_line = line.lower()

            sql_keywords = [
                "select ",
                "insert ",
                "update ",
                "delete ",
                "from ",
                "where "
            ]

            contains_sql = any(keyword in lower_line for keyword in sql_keywords)

            if contains_sql:

                if (
                    "+" in line
                    or "%" in line
                    or ".format(" in line
                    or "f\"" in line
                    or "f'" in line
                ):
                    self.add_result(
                        "Potential SQL Injection",
                        "HIGH",
                        index,
                        "An SQL query appears to be constructed using string concatenation or formatting. If untrusted input is included, this may allow SQL injection.",
                        "Use parameterized queries or prepared statements instead of building SQL queries with user-controlled strings."
                    )

    # ---------------------------------------------------------
    # 4. Hardcoded Secrets
    # ---------------------------------------------------------
    def check_hardcoded_secrets(self):
        secret_names = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "token",
            "access_key",
            "private_key"
        ]

        for node in ast.walk(self.tree):

            if isinstance(node, ast.Assign):

                for target in node.targets:

                    if isinstance(target, ast.Name):

                        variable_name = target.id.lower()

                        if any(secret in variable_name for secret in secret_names):

                            if isinstance(node.value, ast.Constant):
                                value = node.value.value

                                if isinstance(value, str) and value.strip():
                                    self.add_result(
                                        "Hardcoded Secret",
                                        "HIGH",
                                        node.lineno,
                                        f"The variable '{target.id}' contains a hardcoded sensitive value.",
                                        "Do not store passwords, API keys, tokens, or other secrets directly in source code. Use environment variables or a secure secret manager."
                                    )

    # ---------------------------------------------------------
    # 5. Path Traversal
    # ---------------------------------------------------------
    def check_path_traversal(self):
        for node in ast.walk(self.tree):

            if isinstance(node, ast.Call):

                if isinstance(node.func, ast.Name) and node.func.id == "open":

                    if node.args:

                        file_argument = node.args[0]

                        # open(variable)
                        if isinstance(file_argument, ast.Name):
                            self.add_result(
                                "Potential Path Traversal",
                                "HIGH",
                                node.lineno,
                                "open() uses a variable that may contain user-controlled file path data.",
                                "Validate and restrict file paths. Use a trusted base directory and prevent access to unintended files."
                            )

                        # open(f"...")
                        elif isinstance(file_argument, ast.JoinedStr):
                            self.add_result(
                                "Potential Path Traversal",
                                "HIGH",
                                node.lineno,
                                "open() uses a dynamically constructed file path that may contain user-controlled data.",
                                "Validate and restrict file paths. Use a trusted base directory and prevent access to unintended files."
                            )

    # ---------------------------------------------------------
    # 6. Weak Password Hashing
    # ---------------------------------------------------------
    def check_weak_hashing(self):
        weak_hashes = [
            "md5",
            "sha1"
        ]

        for node in ast.walk(self.tree):

            if isinstance(node, ast.Call):

                if isinstance(node.func, ast.Attribute):

                    function_name = node.func.attr.lower()

                    if function_name in weak_hashes:

                        self.add_result(
                            "Weak Cryptographic Hash",
                            "MEDIUM",
                            node.lineno,
                            f"{function_name.upper()} is considered weak for password or security-sensitive hashing.",
                            "Use a modern password hashing algorithm such as Argon2id, bcrypt, or scrypt."
                        )

    # ---------------------------------------------------------
    # 7. Insecure HTTP
    # ---------------------------------------------------------
    def check_insecure_http(self):
        lines = self.code.splitlines()

        for index, line in enumerate(lines, start=1):

            if "http://" in line.lower():
                self.add_result(
                    "Insecure HTTP Connection",
                    "MEDIUM",
                    index,
                    "The code contains an HTTP URL that does not provide transport encryption.",
                    "Use HTTPS instead of HTTP when transmitting sensitive or security-sensitive information."
                )

    # ---------------------------------------------------------
    # Main Analysis
    # ---------------------------------------------------------
    def analyze(self):

        if self.tree is None:
            return self.results

        self.check_dangerous_functions()
        self.check_command_injection()
        self.check_sql_injection()
        self.check_hardcoded_secrets()
        self.check_path_traversal()
        self.check_weak_hashing()
        self.check_insecure_http()

        return self.results


# -------------------------------------------------------------
# Standalone testing
# -------------------------------------------------------------
if __name__ == "__main__":

    print("=" * 60)
    print("          SafePyScript Security Analysis")
    print("=" * 60)

    test_code = """
name = input("Enter your name: ")

password = "admin123"

print(name)
"""

    analyzer = SecurityAnalyzer(test_code)

    results = analyzer.analyze()

    if not results:
        print("\nNo security vulnerabilities detected.")

    for result in results:

        print("\n--- Security Issue ---")

        print("Vulnerability:")
        print(result["vulnerability"])

        print("Severity:")
        print(result["severity"])

        print("Line:")
        print(result["line"])

        print("Description:")
        print(result["description"])

        print("Recommendation:")
        print(result["recommendation"])

        print("-" * 60)