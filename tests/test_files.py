import json

from src.utils.files import write_json, write_text


def test_write_json_supports_stdout(capfd):
    write_json("-", {"tool": "guardian", "ok": True})

    out, err = capfd.readouterr()

    assert json.loads(out) == {"tool": "guardian", "ok": True}
    assert err == ""


def test_write_text_supports_stdout(capfd):
    write_text("-", "hello")

    out, err = capfd.readouterr()

    assert out.replace("\r\n", "\n") == "hello\n"
    assert err == ""
