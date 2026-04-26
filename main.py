import argparse
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Browser Forensics Tool — offline artifacts analyzer"
    )
    parser.add_argument(
        "--input", required=True, type=Path,
        help="Path to browser profile directory"
    )
    parser.add_argument(
        "--browser", required=True, choices=["chrome", "firefox"],
        help="Browser type"
    )
    parser.add_argument(
        "--report", default="html", choices=["html", "csv"],
        help="Output report format (default: html)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"[*] Input:   {args.input}")
    print(f"[*] Browser: {args.browser}")
    print(f"[*] Report:  {args.report}")
    print("[*] Analysis not yet implemented ")


if __name__ == "__main__":
    main()