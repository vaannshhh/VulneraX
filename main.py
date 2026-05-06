"""
VulneraX — Entry Point
========================
Routes execution to GUI, CLI, or API depending on arguments.

Usage
-----
  python main.py              → Launch GUI
  python main.py gui          → Launch GUI
  python main.py scan <tgt>   → CLI scan
  python main.py api          → Start API server
  python main.py --help       → Full help
"""

import sys
import os

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    banner = """\033[32m
██╗  ██╗██╗   ██╗███████╗██╗  ██╗███████╗███╗   ██╗██████╗ ██████╗ 
██║ ██╔╝██║   ██║██╔════╝██║  ██║╚══███╔╝████╗  ██║██╔══██╗██╔══██╗
█████╔╝ ██║   ██║███████╗███████║  ███╔╝ ██╔██╗ ██║██║  ██║██████╔╝
██╔═██╗ ██║   ██║╚════██║██╔══██║ ███╔╝  ██║╚██╗██║██║  ██║██╔══██╗
██║  ██╗╚██████╔╝███████║██║  ██║███████╗██║ ╚████║██████╔╝██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
             v2.1.2\033[0m
"""
    print(banner)

    args = sys.argv[1:]

    # If arguments are passed, route to the Click CLI
    if args:
        from cli import cli
        cli()
        return

    # Super simple interactive mode for "no bhasad" experience
    print("=" * 67)
    print(" ⚡ VulneraX — Simple Interactive Mode")
    print("=" * 67)
    
    target = input("\nEnter Domain/IP/URL to scan: ").strip()
    if not target:
        print("No target entered. Exiting.")
        sys.exit(0)

    print("\n[+] Starting scan... (Skipping ZAP to avoid background daemon errors)\n")
    
    # Programmatically call the CLI 'scan' command
    # We use custom native scanners to guarantee 0 errors on fresh computers
    sys.argv = ["main.py", "scan", target, "--custom", "--scanners", "native_port_scanner,native_web_scanner,header_security"]
    
    from cli import cli
    try:
        cli()
    except SystemExit:
        pass


if __name__ == "__main__":
    main()
