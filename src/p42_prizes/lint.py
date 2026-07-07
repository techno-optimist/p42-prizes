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
}

FLOAT_DTYPE_NAMES = {
    "float",
    "float16",
    "float32",
    "float64",
    "double",
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

    def add(self, node: ast.AST, code: str, message: str) -> None:
        self.findings.append(
            Finding(self.path, getattr(node, "lineno", 1), code, message)
        )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, float):
            self.add(node, "R1_FLOAT_LITERAL", "float literals are banned on the certified path")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root in DISALLOWED_IMPORT_ROOTS:
                self.add(node, "R3_IMPORT", f"import of nondeterministic or float-prone module '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            root = node.module.split(".", 1)[0]
            if root in DISALLOWED_IMPORT_ROOTS:
                self.add(node, "R3_IMPORT", f"import from nondeterministic or float-prone module '{node.module}'")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in FLOAT_DTYPE_NAMES:
            self.add(node, "R1_FLOAT_NAME", f"float-like name '{node.id}' is banned")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "math":
            self.add(node, "R1_MATH_ATTR", "math.* is banned on the certified path")
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

