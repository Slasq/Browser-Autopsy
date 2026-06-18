import os
import shutil
import sqlite3
from pathlib import Path

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

    def test_wal_file_copied_alongside_db(self, tmp_path):
        """Jeśli obok bazy jest plik -wal, open_db musi go skopiować do tempdir."""
        p = tmp_path / "History"
        _make_valid_db(p)
        wal = Path(str(p) + "-wal")
        wal.write_bytes(b"\x00" * 32)  # fake WAL — wystarczy żeby sprawdzić kopię
        conn, tmp_dir = open_db(p)
        try:
            assert (tmp_dir / "History-wal").exists()
        finally:
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_shm_file_copied_alongside_db(self, tmp_path):
        """Analogicznie dla pliku -shm (shared memory)."""
        p = tmp_path / "places.sqlite"
        _make_valid_db(p)
        shm = Path(str(p) + "-shm")
        shm.write_bytes(b"\x00" * 32)
        conn, tmp_dir = open_db(p)
        try:
            assert (tmp_dir / "places.sqlite-shm").exists()
        finally:
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_open_db_works_without_wal(self, tmp_path):
        """Brak pliku WAL nie powoduje błędu — open_db go pomija."""
        p = tmp_path / "History"
        _make_valid_db(p)
        conn, tmp_dir = open_db(p)
        try:
            assert not (tmp_dir / "History-wal").exists()
        finally:
            conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestSha256File:

    def test_returns_hex_string_of_length_64(self, tmp_path):
        p = tmp_path / "f.bin"
        p.write_bytes(b"hello")
        digest = sha256_file(p)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_known_content_matches_expected_hash(self, tmp_path):
        import hashlib
        content = b"browser-autopsy test content"
        p = tmp_path / "f.bin"
        p.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert sha256_file(p) == expected

    def test_empty_file_returns_sha256_of_empty(self, tmp_path):
        import hashlib
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        assert sha256_file(p) == hashlib.sha256(b"").hexdigest()

    def test_two_identical_files_same_hash(self, tmp_path):
        content = b"same content"
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(content)
        b.write_bytes(content)
        assert sha256_file(a) == sha256_file(b)

    def test_different_content_different_hash(self, tmp_path):
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(b"aaa")
        b.write_bytes(b"bbb")
        assert sha256_file(a) != sha256_file(b)