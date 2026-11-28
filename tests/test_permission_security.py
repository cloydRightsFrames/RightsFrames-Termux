"""Fail-closed permission and atomic-write regression tests."""

import errno
import os
import stat

import pytest

from core import rf_core as rf


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    path = tmp_path / "ledger"
    monkeypatch.setattr(rf, "DATA_DIR", path)
    return path


def test_atomic_roundtrip(data_dir):
    target = data_dir / "record"
    for payload in (b"original", b"replacement"):
        rf._atomic_write(target, payload, 0o600)
        assert target.read_bytes() == payload
        assert not list(data_dir.glob(".record.*"))


@posix_only
def test_restrictive_creation(data_dir, monkeypatch):
    observed = []
    original = os.open

    def inspect(path, *args, **kwargs):
        observed.append(stat.S_IMODE(data_dir.lstat().st_mode))
        return original(path, *args, **kwargs)

    previous = os.umask(0)
    try:
        with monkeypatch.context() as m:
            m.setattr(os, "open", inspect)
            rf._secure_directory()
    finally:
        os.umask(previous)
    assert observed == [0o700]


@posix_only
def test_existing_directory_repair(data_dir):
    data_dir.mkdir()
    data_dir.chmod(0o755)
    rf._secure_directory()
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700


@posix_only
@pytest.mark.parametrize("denial", [True, False])
def test_directory_permission_failure(data_dir, monkeypatch, denial):
    data_dir.mkdir()
    data_dir.chmod(0o755)

    def fail(fd, mode):
        if denial:
            raise PermissionError("injected failure")

    with monkeypatch.context() as m:
        m.setattr(os, "fchmod", fail)
        with pytest.raises(PermissionError):
            rf._secure_directory()


@posix_only
def test_directory_symlink_rejected(data_dir, tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    victim.chmod(0o755)
    data_dir.symlink_to(victim, target_is_directory=True)
    with pytest.raises(OSError):
        rf._secure_directory()
    assert data_dir.is_symlink()
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755


def test_regular_file_rejected(data_dir):
    data_dir.write_bytes(b"untouched")
    with pytest.raises(OSError):
        rf._secure_directory()
    assert data_dir.read_bytes() == b"untouched"


@posix_only
def test_foreign_owner_rejected(data_dir, monkeypatch):
    data_dir.mkdir()
    foreign = os.geteuid() + 1
    with monkeypatch.context() as m:
        m.setattr(os, "geteuid", lambda: foreign)
        with pytest.raises(PermissionError):
            rf._secure_directory()


@posix_only
def test_directory_identity_swap(data_dir, tmp_path, monkeypatch):
    data_dir.mkdir()
    original = os.fchmod
    displaced = tmp_path / "displaced"

    def swap(fd, mode):
        original(fd, mode)
        data_dir.rename(displaced)
        data_dir.mkdir(mode=0o700)

    with monkeypatch.context() as m:
        m.setattr(os, "fchmod", swap)
        with pytest.raises(PermissionError):
            rf._secure_directory()


@posix_only
def test_atomic_file_permissions(data_dir):
    target = data_dir / "record"
    rf._atomic_write(target, b"private", 0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@posix_only
@pytest.mark.parametrize("denial", [True, False])
def test_atomic_permission_failure(data_dir, monkeypatch, denial):
    target = data_dir / "record"
    rf._atomic_write(target, b"original", 0o600)
    original = os.fchmod

    def fail(fd, mode):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            return original(fd, mode)
        if denial:
            raise PermissionError("injected failure")

    with monkeypatch.context() as m:
        m.setattr(os, "fchmod", fail)
        with pytest.raises(PermissionError):
            rf._atomic_write(target, b"unsafe", 0o400)
    assert target.read_bytes() == b"original"
    assert not list(data_dir.glob(".record.*"))


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_atomic_failure_preserves_original(data_dir, monkeypatch, operation):
    target = data_dir / "record"
    rf._atomic_write(target, b"original", 0o600)

    def deny(*args, **kwargs):
        raise OSError("injected failure")

    with monkeypatch.context() as m:
        m.setattr(os, operation, deny)
        with pytest.raises(OSError):
            rf._atomic_write(target, b"unsafe", 0o600)
    assert target.read_bytes() == b"original"
    assert not list(data_dir.glob(".record.*"))


def test_fdopen_failure_closes_descriptor(data_dir, monkeypatch):
    target = data_dir / "record"
    rf._atomic_write(target, b"original", 0o600)
    captured = []

    def deny(fd, *args, **kwargs):
        captured.append(fd)
        raise OSError("injected fdopen failure")

    with monkeypatch.context() as m:
        m.setattr(os, "fdopen", deny)
        with pytest.raises(OSError):
            rf._atomic_write(target, b"unsafe", 0o600)
        assert len(captured) == 1
        with pytest.raises(OSError) as error:
            os.fstat(captured[0])
        assert error.value.errno == errno.EBADF
    assert target.read_bytes() == b"original"
    assert not list(data_dir.glob(".record.*"))


def test_external_destination_rejected(data_dir, tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    with pytest.raises(ValueError):
        rf._atomic_write(outside, b"unsafe", 0o600)
    assert outside.read_bytes() == b"untouched"


@posix_only
def test_destination_symlink_target_preserved(data_dir, tmp_path):
    rf._secure_directory()
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    link = data_dir / "link"
    link.symlink_to(outside)
    rf._atomic_write(link, b"replacement", 0o600)
    assert not link.is_symlink()
    assert link.read_bytes() == b"replacement"
    assert outside.read_bytes() == b"untouched"


@posix_only
def test_post_rename_durability_failure(data_dir, monkeypatch):
    target = data_dir / "record"
    rf._atomic_write(target, b"original", 0o600)
    original = os.fsync

    def deny_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory sync failure")
        return original(fd)

    with monkeypatch.context() as m:
        m.setattr(os, "fsync", deny_directory)
        with pytest.raises(OSError):
            rf._atomic_write(target, b"committed", 0o600)
    assert target.read_bytes() == b"committed"
    assert not list(data_dir.glob(".record.*"))
