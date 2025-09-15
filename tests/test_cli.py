from pylynis.cli import build_parser

def test_cli_builds_and_has_commands():
    p = build_parser()
    args = p.parse_args(["audit", "system", "--format", "json"])  # should parse
    assert args.command == "audit"
    assert args.subject == "system"
    assert args.fmt == "json"
