from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


DISALLOWED_IMPORT_ROOTS = {
    "math",
    "random",
    "secrets",
    "time",
    "datetime",
    "socket",
    "requests",
    "urllib",
    "http",
    "subprocess",
    "ctypes",
    "importlib",
    "platform",
    "uuid",
    "tempfile",
    "threading",
    "multiprocessing",
    "numpy",
    "operator",
    "scipy",
    "pandas",
    "torch",
}

# `os` and `sys` have legitimate plumbing uses (exit codes, path building), so
# they are not banned wholesale; only their nondeterministic entry points are.
DISALLOWED_ATTRIBUTES = {
    ("os", "urandom"),
    ("os", "getrandom"),
    ("os", "getenv"),
    ("os", "environ"),
}

FLOAT_DTYPE_NAMES = {
    "float",
    "float16",
    "float32",
    "float64",
    "double",
}

# Callables that defeat static analysis by dispatching to code chosen at
# runtime; on the certified path they can smuggle banned imports or float math
# past the name/import checks below.
DYNAMIC_DISPATCH_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "getattr",
    "setattr",
}

DISALLOWED_IMPORTED_SYMBOLS = {
    "builtins": FLOAT_DTYPE_NAMES | DYNAMIC_DISPATCH_NAMES,
    "os": {attribute for module, attribute in DISALLOWED_ATTRIBUTES if module == "os"},
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    code: str
    message: str

    def format(self, root: Path) -> str:
        try:
            rel = self.path.relative_to(root)
        except ValueError:
            rel = self.path
        return f"{rel}:{self.line}: {self.code} {self.message}"


class ExactPathVisitor(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.findings: list[Finding] = []
        self.module_aliases: dict[str, str] = {}
        self.symbol_aliases: dict[str, tuple[str, str]] = {}

    def add(self, node: ast.AST, code: str, message: str) -> None:
        self.findings.append(
            Finding(self.path, getattr(node, "lineno", 1), code, message)
        )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, float):
            self.add(node, "R1_FLOAT_LITERAL", "float literals are banned on the certified path")
        elif isinstance(node.value, complex):
            self.add(node, "R1_COMPLEX_LITERAL", "complex literals are banned on the certified path")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # Python 3 `/` (true division) always returns a float when its operands
        # are ints, so a boundary decision like `(seed - score) / seed >= t`
        # silently becomes float-influenced and can flip at the frontier. Exact
        # ratios must use `Fraction(numerator, denominator)` or `//`.
        if isinstance(node.op, ast.Div):
            self.add(
                node,
                "R1_TRUE_DIVISION",
                "true division '/' yields float; use Fraction(a, b) for exact ratios or '//' for integers",
            )
        # `**` returns a float for negative or non-integer exponents. Allow only
        # a statically non-negative integer literal exponent.
        if isinstance(node.op, ast.Pow):
            exponent = node.right
            safe = isinstance(exponent, ast.Constant) and isinstance(exponent.value, int) and exponent.value >= 0
            if not safe:
                self.add(
                    node,
                    "R1_FLOAT_POW",
                    "'**' yields float for negative or non-integer exponents; use exact integer/Fraction arithmetic",
                )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            local_name = alias.asname or root
            self.module_aliases[local_name] = root
            if root in DISALLOWED_IMPORT_ROOTS:
                self.add(node, "R3_IMPORT", f"import of nondeterministic or float-prone module '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            root = node.module.split(".", 1)[0]
            if root in DISALLOWED_IMPORT_ROOTS:
                self.add(node, "R3_IMPORT", f"import from nondeterministic or float-prone module '{node.module}'")
            for alias in node.names:
                local_name = alias.asname or alias.name
                self.symbol_aliases[local_name] = (root, alias.name)
                if alias.name in DISALLOWED_IMPORTED_SYMBOLS.get(root, set()):
                    self.add(
                        node,
                        "R3_IMPORT_ALIAS",
                        f"imported alias '{local_name}' exposes banned symbol '{root}.{alias.name}'",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id in DYNAMIC_DISPATCH_NAMES:
            self.add(
                node,
                "R2_DYNAMIC_DISPATCH",
                f"'{func.id}' dispatches to runtime-chosen code and defeats exact-path analysis",
            )
        if isinstance(func, ast.Name) and func.id in self.symbol_aliases:
            module, symbol = self.symbol_aliases[func.id]
            if module == "builtins" and symbol in FLOAT_DTYPE_NAMES:
                self.add(
                    node,
                    "R1_FLOAT_ALIAS",
                    f"'{func.id}' aliases float-like callable '{module}.{symbol}'",
                )
            if module == "builtins" and symbol in DYNAMIC_DISPATCH_NAMES:
                self.add(
                    node,
                    "R2_DYNAMIC_DISPATCH",
                    f"'{func.id}' aliases runtime dispatch callable '{module}.{symbol}'",
                )
        if isinstance(func, ast.Name) and func.id == "pow" and len(node.args) >= 2:
            exponent = node.args[1]
            safe = isinstance(exponent, ast.Constant) and isinstance(exponent.value, int) and exponent.value >= 0
            if not safe:
                self.add(
                    node,
                    "R1_FLOAT_POW",
                    "'pow' yields float for negative or non-integer exponents; use exact integer/Fraction arithmetic",
                )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in FLOAT_DTYPE_NAMES:
            self.add(node, "R1_FLOAT_NAME", f"float-like name '{node.id}' is banned")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            module = self.module_aliases.get(node.value.id, node.value.id)
            if module == "math":
                self.add(node, "R1_MATH_ATTR", "math.* is banned on the certified path")
            if module == "builtins" and node.attr in DYNAMIC_DISPATCH_NAMES:
                self.add(
                    node,
                    "R2_DYNAMIC_DISPATCH",
                    f"runtime dispatch entry point '{node.value.id}.{node.attr}' is banned",
                )
            if (module, node.attr) in DISALLOWED_ATTRIBUTES:
                self.add(
                    node,
                    "R3_NONDETERMINISTIC_ATTR",
                    f"nondeterministic entry point '{node.value.id}.{node.attr}' is banned on the certified path",
                )
        if node.attr in FLOAT_DTYPE_NAMES:
            self.add(node, "R1_FLOAT_ATTR", f"float-like attribute '{node.attr}' is banned")
        self.generic_visit(node)


def lint_python_file(path: Path) -> list[Finding]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = ExactPathVisitor(path)
    visitor.visit(tree)
    return visitor.findings


def lint_verifier(problem_dir: str | Path) -> list[Finding]:
    verifier_dir = Path(problem_dir) / "verifier"
    findings: list[Finding] = []
    for path in sorted(verifier_dir.rglob("*.py")):
        findings.extend(lint_python_file(path))
    return findings
