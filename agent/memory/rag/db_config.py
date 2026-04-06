"""RAG PostgreSQL connection configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class RAGDatabaseConfig:
    """PostgreSQL connection settings for RAG memory.

    Reads from environment variables with sensible local-development defaults.
    """

    host: str = "localhost"
    port: int = 5432
    dbname: str = "phantom"
    user: str = "noir"
    password: str = ""

    @classmethod
    def from_env(cls) -> RAGDatabaseConfig:
        """Create config from ``DB_*`` environment variables."""
        try:
            port = int(os.environ.get("DB_PORT", "5432"))
        except ValueError:
            port = 5432
        return cls(
            host=os.environ.get("DB_HOST", "localhost"),
            port=port,
            dbname=os.environ.get("DB_NAME", "phantom"),
            user=os.environ.get("DB_USER", "noir"),
            password=os.environ.get("DB_PASSWORD", ""),
        )

    def to_dsn(self) -> str:
        """Return a libpq-style connection string."""
        parts = [
            f"host={self.host}",
            f"port={self.port}",
            f"dbname={self.dbname}",
            f"user={self.user}",
        ]
        if self.password:
            parts.append(f"password={self.password}")
        return " ".join(parts)

    def to_dict(self) -> dict[str, str | int]:
        """Return kwargs suitable for ``psycopg2.connect()``."""
        d: dict[str, str | int] = {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
        }
        if self.password:
            d["password"] = self.password
        return d
