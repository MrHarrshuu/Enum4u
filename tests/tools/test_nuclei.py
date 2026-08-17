from enum4u.tools.nuclei import NucleiTool


def test_nuclei_tool_name():
    tool = NucleiTool()

    assert tool.name == "nuclei"


def test_build_command_fast():
    tool = NucleiTool()

    command = tool.build_command(
        "http://127.0.0.1:8000",
        "fast",
    )

    assert command == [
        "nuclei",
        "-u",
        "http://127.0.0.1:8000",
        "-jsonl",
        "-silent",
        "-severity",
        "critical,high,medium",
    ]


def test_build_command_deep():
    tool = NucleiTool()

    command = tool.build_command(
        "http://127.0.0.1:8000",
        "deep",
    )

    assert command == [
        "nuclei",
        "-u",
        "http://127.0.0.1:8000",
        "-jsonl",
        "-silent",
        "-severity",
        "critical,high,medium,low,info",
    ]


def test_build_command_rejects_empty_target():
    tool = NucleiTool()

    try:
        tool.build_command("", "fast")
    except ValueError as exc:
        assert "target" in str(exc).lower()
    else:
        raise AssertionError(
            "Empty target should raise ValueError"
        )


def test_parse_output():
    tool = NucleiTool()

    output = """
{"template-id":"test-template","info":{"name":"Test Vulnerability","severity":"high"},"matched-at":"http://127.0.0.1:8000/","type":"http","host":"127.0.0.1:8000"}
"""

    findings = tool.parse_output(output)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["template_id"] == "test-template"
    assert finding["name"] == "Test Vulnerability"
    assert finding["severity"] == "high"
    assert finding["matched_at"] == "http://127.0.0.1:8000/"
    assert finding["type"] == "http"
    assert finding["host"] == "127.0.0.1:8000"


def test_parse_output_ignores_invalid_json():
    tool = NucleiTool()

    output = """
this is not json
{"template-id":"valid","info":{"name":"Valid","severity":"medium"}}
also invalid
"""

    findings = tool.parse_output(output)

    assert len(findings) == 1
    assert findings[0]["template_id"] == "valid"


def test_parse_empty_output():
    tool = NucleiTool()

    assert tool.parse_output("") == []