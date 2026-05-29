import os
import shutil
import sqlite3

import pytest

from extractors.base import (
    ArtifactError,
    ArtifactNotFoundError,
    CorruptedDatabaseError,
    open_db,
    sha256_file,
)

# helpers
def _make_valid_db(path) -> None:
    """Create a small, valid SQLite DB at `path`."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(50)])
    conn.commit()
    conn.close()


# testy
class TestMissingFile:

    def test_open_db_raises_artifact_not_found(self, tmp_path):
        with pytest.raises(ArtifactNotFoundError):
            open_db(tmp_path / "nope.sqlite")

    def test_artifact_not_found_is_file_not_found(self, tmp_path):
        # kompatybilność wsteczna stare `except FileNotFoundError` ma dalej łapać
        with pytest.raises(FileNotFoundError):
            open_db(tmp_path / "nope.sqlite")

    def test_sha256_missing_file_raises_artifact_not_found(self, tmp_path):
        with pytest.raises(ArtifactNotFoundError):
            sha256_file(tmp_path / "nope")

    def test_message_contains_path(self, tmp_path):
        with pytest.raises(ArtifactNotFoundError) as ei:
            open_db(tmp_path / "History")
        assert "History" in str(ei.value)


class TestCorruptedDatabase:

    def test_garbage_file_raises_corrupted(self, tmp_path):
        """Śmieci zamiast bazy → CorruptedDatabaseError (file is not a database)."""
        p = tmp_path / "History"
        p.write_bytes(b"definitely not a sqlite file \x00\x01\x02" * 20)
        with pytest.raises(CorruptedDatabaseError):
            open_db(p)

    def test_truncated_db_raises_corrupted(self, tmp_path):
        """Poprawny nagłówek, rozwalony środek → malformed disk image."""
        good = tmp_path / "good.sqlite"
        _make_valid_db(good)
        data = good.read_bytes()
        broken = tmp_path / "History"
        broken.write_bytes(data[: len(data) // 2] + b"\x00" * 256)
        with pytest.raises(CorruptedDatabaseError):
            open_db(broken)

    def test_corrupted_is_not_file_not_found(self, tmp_path):
        assert not issubclass(CorruptedDatabaseError, FileNotFoundError)
        p = tmp_path / "History"
        p.write_bytes(b"garbage" * 100)
        with pytest.raises(CorruptedDatabaseError):
            open_db(p)

    def test_corrupted_is_artifact_error(self):
        assert issubclass(CorruptedDatabaseError, ArtifactError)

    def test_no_tempdir_leak_on_corruption(self, tmp_path, monkeypatch):
        """Kopia tymczasowa musi być sprzątnięta, gdy walidacja padnie."""
        import extractors.base as base
        created = []
        real_mkdtemp = base.tempfile.mkdtemp

        def spy(*a, **kw):
            d = real_mkdtemp(*a, **kw)
            created.append(d)
            return d

        monkeypatch.setattr(base.tempfile, "mkdtemp", spy)
        p = tmp_path / "History"
        p.write_bytes(b"garbage" * 100)
        with pytest.raises(CorruptedDatabaseError):
            open_db(p)
        assert created and not os.path.exists(created[0])


class TestValidDatabase:

    def test_valid_db_opens_and_queries(self, tmp_path):
        p = tmp_path / "History"
        _make_valid_db(p)
        conn, tmp_dir = open_db(p)
        try:
            assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 50
        finally:
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_valid_db_uses_row_factory(self, tmp_path):
        p = tmp_path / "History"
        _make_valid_db(p)
        conn, tmp_dir = open_db(p)
        try:
            assert conn.execute("SELECT x FROM t LIMIT 1").fetchone()["x"] == 0
        finally:
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)