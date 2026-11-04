from pathlib import Path

__version__: str

def scan_path(
    path: Path,
    hash: bool = ...,
    max_decompressed: int = ...,
    output: str = ...,
    min_severity: str = ...,
) -> str: ...
def scan_bytes(
    data: bytes,
    name: str = ...,
    hash: bool = ...,
    max_decompressed: int = ...,
    declared_size: int | None = ...,
) -> str: ...
def render(reports_json: str, output: str = ..., min_severity: str = ...) -> str: ...
def rules() -> str: ...
def rules_markdown() -> str: ...
def serve(addr: str = ..., max_body: int = ..., threads: int = ...) -> None: ...
