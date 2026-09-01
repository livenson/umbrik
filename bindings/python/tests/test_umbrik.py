"""Round-trip and failure-mode tests for the Python bindings."""

import pytest

import umbrik

PASSWORD = "correct-horse-battery-staple-õäöü"
SECRET = b"0123456789abcdef0123456789abcdef"
FILES = {"hello.txt": b"Tere, maailm!\n", "notes.md": b"# notes\n\nOaou\n"}


def test_password_round_trip():
    blob = umbrik.encrypt(FILES, password=("pw-label", PASSWORD))
    assert blob[:4] == b"CDOC"
    assert umbrik.decrypt(blob, password=PASSWORD) == FILES


def test_secret_round_trip():
    blob = umbrik.encrypt(FILES, secret=("sk-label", SECRET))
    assert umbrik.decrypt(blob, secret=SECRET) == FILES


def test_multiple_recipients_each_open_the_container():
    blob = umbrik.encrypt(FILES, password=("pw", PASSWORD), secret=("sk", SECRET))
    assert umbrik.decrypt(blob, password=PASSWORD) == FILES
    assert umbrik.decrypt(blob, secret=SECRET) == FILES


def test_non_ascii_names_and_contents_survive():
    files = {"õäöü.txt": "sisu: jõudis\n".encode()}
    blob = umbrik.encrypt(files, password=("l", PASSWORD))
    assert umbrik.decrypt(blob, password=PASSWORD) == files


def test_binary_content_is_unchanged():
    files = {"random.bin": bytes(range(256)) * 40}
    blob = umbrik.encrypt(files, password=("l", PASSWORD))
    assert umbrik.decrypt(blob, password=PASSWORD) == files


def test_recipients_readable_without_a_key():
    blob = umbrik.encrypt(FILES, password=("my-label", PASSWORD))
    recipients = umbrik.recipients(blob)
    assert len(recipients) == 1
    assert recipients[0].scheme == "SC06"
    assert recipients[0].label.startswith("data:,")
    assert recipients[0].display == "my-label (pw)"


def test_wrong_password_raises_wrong_key():
    blob = umbrik.encrypt(FILES, password=("l", PASSWORD))
    with pytest.raises(umbrik.WrongKeyError):
        umbrik.decrypt(blob, password="not-the-password")


def test_key_of_the_wrong_kind_raises_no_matching_recipient():
    blob = umbrik.encrypt(FILES, secret=("sk", SECRET))
    with pytest.raises(umbrik.NoMatchingRecipientError):
        umbrik.decrypt(blob, password=PASSWORD)


def test_tampered_payload_raises_authentication_error():
    blob = bytearray(umbrik.encrypt(FILES, password=("l", PASSWORD)))
    blob[-20] ^= 0xFF
    with pytest.raises(umbrik.AuthenticationError):
        umbrik.decrypt(bytes(blob), password=PASSWORD)


def test_garbage_raises_container_error():
    with pytest.raises(umbrik.ContainerError):
        umbrik.decrypt(b"not a container at all", password=PASSWORD)


def test_every_error_inherits_the_base_class():
    blob = umbrik.encrypt(FILES, password=("l", PASSWORD))
    with pytest.raises(umbrik.UmbrikError):
        umbrik.decrypt(blob, password="wrong")


def test_zip_bomb_is_rejected_and_the_message_explains():
    blob = umbrik.encrypt({"bomb": b"\0" * 4_000_000}, password=("l", PASSWORD))
    with pytest.raises(umbrik.LimitExceededError) as excinfo:
        umbrik.decrypt(blob, password=PASSWORD)
    assert "max_compression_ratio" in str(excinfo.value)


def test_limits_can_be_raised_for_a_trusted_container():
    blob = umbrik.encrypt({"bomb": b"\0" * 4_000_000}, password=("l", PASSWORD))
    out = umbrik.decrypt(
        blob, password=PASSWORD, limits=umbrik.Limits(max_compression_ratio=1_000_000)
    )
    assert len(out["bomb"]) == 4_000_000


def test_entry_count_limit():
    files = {f"f{i}.txt": b"x" for i in range(20)}
    blob = umbrik.encrypt(files, password=("l", PASSWORD))
    with pytest.raises(umbrik.LimitExceededError):
        umbrik.decrypt(blob, password=PASSWORD, limits=umbrik.Limits(max_entries=5))


def test_limits_defaults_are_exposed():
    limits = umbrik.Limits()
    assert limits.max_compression_ratio == 100
    assert limits.max_entries == 1000
    assert "max_compression_ratio" in repr(limits)


def test_encrypt_requires_a_recipient():
    with pytest.raises(umbrik.UmbrikError):
        umbrik.encrypt(FILES)


def test_encrypt_requires_files():
    with pytest.raises(umbrik.UmbrikError):
        umbrik.encrypt({}, password=("l", PASSWORD))


def test_decrypt_requires_key_material():
    blob = umbrik.encrypt(FILES, password=("l", PASSWORD))
    with pytest.raises(umbrik.UmbrikError):
        umbrik.decrypt(blob)


def test_unsafe_entry_names_are_refused_at_encrypt_time():
    with pytest.raises(umbrik.UnsafeArchiveError):
        umbrik.encrypt({"../escaped.txt": b"x"}, password=("l", PASSWORD))


def test_module_exposes_a_version():
    assert umbrik.__version__
