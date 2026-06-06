from pathlib import Path

from osint_recon.config import Config


def test_parse_env_file(tmp_path):
    env = tmp_path / "apis.env"
    env.write_text(
        '# comment line\nSHODAN_API_KEY=abc123\nBLANK=\nQUOTED="xyz"\n  SPACED = value \n'
    )
    cfg = Config.load(env)
    assert cfg.get("SHODAN_API_KEY") == "abc123"
    assert cfg.has("SHODAN_API_KEY")
    assert cfg.get("BLANK") is None  # blank values are dropped
    assert cfg.get("QUOTED") == "xyz"  # surrounding quotes stripped
    assert cfg.get("SPACED") == "value"  # whitespace trimmed


def test_missing_file_is_empty():
    cfg = Config.load(Path("/nonexistent/apis.env"))
    assert cfg.get("DEFINITELY_NOT_SET_XYZ") is None
    assert cfg.has("DEFINITELY_NOT_SET_XYZ") is False
