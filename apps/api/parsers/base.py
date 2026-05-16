from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ParsedFunction:
    name: str
    file_path: str
    line: int
    end_line: int
    source_code: str
    parameters: list[str]


class BaseParser(ABC):
    @abstractmethod
    def parse_file(self, file_path: str, source: str) -> list[ParsedFunction]:
        ...

    @abstractmethod
    def supported_extensions(self) -> list[str]:
        ...
