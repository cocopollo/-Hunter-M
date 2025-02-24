#!/usr/bin/env python3
"""
Hunter M - A macOS DFIR Artifact Collection and Analysis Tool
--------------------------------------------------------------
This tool collects a minimal set of forensic artifacts:
  - Login Items
  - Network Connections
  - Extended Zsh History
  - Running Processes

A banner "Hunter M" is displayed at the top of the report.
  
Copyright (c) 2025 [Your Name]
Licensed under the MIT License.
"""

import argparse
import datetime
import logging
import os
import re
import subprocess
import sys
import textwrap

# Optional: Use colorama for colorful terminal output.
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

class HunterM:
    def __init__(self):
        # Only include the four working artifact categories.
        self.artifacts = {
            "login_items": [],
            "network_connections": [],
            "zsh_history": [],
            "running_processes": [],
        }

    def collect_artifacts(self):
        logging.info("Collecting forensic artifacts...")
        self.artifacts["login_items"] = self.get_login_items()
        self.artifacts["network_connections"] = self.get_network_connections()
        self.artifacts["zsh_history"] = self.get_zsh_history_extended()
        self.artifacts["running_processes"] = self.get_running_processes()

    def get_login_items(self):
        logging.debug("Retrieving login items using osascript...")
        try:
            output = subprocess.check_output(
                ["osascript", "-e", 'tell application "System Events" to get the name of every login item'],
                universal_newlines=True
            )
            return [item.strip() for item in output.split(",") if item.strip()]
        except Exception as e:
            logging.error("Error retrieving login items: " + str(e))
            return []

    def get_network_connections(self):
        logging.debug("Retrieving network connections using lsof...")
        connections = []
        try:
            output = subprocess.check_output(["lsof", "-i", "-n", "-P"], universal_newlines=True)
            lines = output.splitlines()
            if lines and lines[0].startswith("COMMAND"):
                lines = lines[1:]
            for line in lines:
                if "ESTABLISHED" in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        command = parts[0]
                        pid = parts[1]
                        user = parts[2]
                        name_field = " ".join(parts[8:])
                        name_clean = name_field.split(" (")[0]
                        endpoints = name_clean.split("->")
                        if len(endpoints) == 2:
                            local = endpoints[0].strip()
                            remote = endpoints[1].strip()
                        else:
                            local = name_clean.strip()
                            remote = ""
                        try:
                            ps_out = subprocess.check_output(["ps", "-p", pid, "-o", "lstart="],
                                                             universal_newlines=True).strip()
                        except Exception:
                            ps_out = "Unknown"
                        # Annotate connection type based on remote port.
                        conn_type = "Other"
                        if ":" in remote:
                            remote_port = remote.split(":")[-1]
                            if remote_port == "22":
                                conn_type = "SSH"
                            elif remote_port == "3389":
                                conn_type = "RDP"
                        connections.append(f"{command} (PID {pid}, {user}, started: {ps_out}): {local} -> {remote} [{conn_type}]")
                    else:
                        connections.append(line)
            return connections
        except Exception as e:
            logging.error("Error retrieving network connections: " + str(e))
            return []

    def get_zsh_history_extended(self):
        logging.debug("Retrieving extended zsh history...")
        home = os.path.expanduser("~")
        path = os.path.join(home, ".zsh_history")
        results = []
        username = os.getenv("USER", "unknown")
        pattern = re.compile(r"^:\s*(\d+):\d+;(.*)$")
        current_sudo_session = None
        cmd_index = 0
        if os.path.exists(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    lines = f.readlines()
                for line in lines:
                    cmd_index += 1
                    line = line.strip()
                    match = pattern.match(line)
                    if match:
                        ts = int(match.group(1))
                        command = match.group(2).strip()
                        dt = datetime.datetime.fromtimestamp(ts)
                        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                        if command.startswith("sudo"):
                            if current_sudo_session is None:
                                current_sudo_session = cmd_index
                            results.append(f"Cmd #{cmd_index} [Session ID: {current_sudo_session}, Privileged]: {dt_str} ({username}) -> {command}")
                        else:
                            current_sudo_session = None
                            results.append(f"Cmd #{cmd_index}: {dt_str} ({username}) -> {command}")
                    else:
                        results.append(f"Cmd #{cmd_index}: {line}")
                return results
            except Exception as e:
                logging.error("Error reading zsh history: " + str(e))
                return []
        else:
            logging.warning(f"zsh history file not found at {path}")
            return []

    def get_running_processes(self):
        logging.debug("Retrieving running processes using ps aux...")
        try:
            output = subprocess.check_output(["ps", "aux"], universal_newlines=True)
            lines = output.splitlines()[1:]
            procs = []
            for line in lines:
                parts = line.split()
                if len(parts) > 10:
                    procs.append(parts[10])
            return sorted(set(procs))
        except Exception as e:
            logging.error("Error retrieving running processes: " + str(e))
            return []

    def generate_report(self, colored=True):
        sections = []
        header_line = "=" * 50
        # Print banner "Hunter M"
        banner = "Hunter M"
        if colored and COLORAMA_AVAILABLE:
            banner_str = Fore.GREEN + banner.center(50) + Style.RESET_ALL
            header = Fore.CYAN + header_line + Style.RESET_ALL
        else:
            banner_str = banner.center(50)
            header = header_line
        sections.append(header)
        sections.append(banner_str)
        sections.append(header + "\n")
        
        # Artifact categories to include.
        categories = [
            ("Login Items", "login_items"),
            ("Network Connections", "network_connections"),
            ("Zsh History (Extended)", "zsh_history"),
            ("Running Processes", "running_processes"),
        ]
        
        for cat_title, key in categories:
            if colored and COLORAMA_AVAILABLE:
                sections.append(Fore.YELLOW + cat_title + ":" + Style.RESET_ALL)
            else:
                sections.append(cat_title + ":")
            items = self.artifacts.get(key, [])
            if not items:
                sections.append("  [None]\n")
            else:
                for item in items:
                    wrapped = textwrap.fill(item, width=70, subsequent_indent="    ")
                    if colored and COLORAMA_AVAILABLE:
                        sections.append("  - " + Fore.WHITE + wrapped + Style.RESET_ALL)
                    else:
                        sections.append("  - " + wrapped)
                sections.append("")
        # No timeline included in this minimal version.
        sections.append(header)
        return "\n".join(sections)

    def export_artifacts(self, export_dir):
        """Export each artifact category into separate text files."""
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
        for key, items in self.artifacts.items():
            filename = os.path.join(export_dir, f"{key}.txt")
            try:
                with open(filename, "w") as f:
                    if items:
                        for item in items:
                            f.write(item + "\n")
                    else:
                        f.write("[None]\n")
                logging.info(f"Exported {key} to {filename}")
            except Exception as e:
                logging.error(f"Error exporting {key}: {e}")

def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def parse_args():
    parser = argparse.ArgumentParser(
        description="Hunter M: A macOS DFIR Artifact Collection and Analysis Tool (Minimal Version)",
        epilog="Publish this tool on GitHub under the MIT License."
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to output the full forensic report (default: stdout)",
        default=None
    )
    parser.add_argument(
        "-l", "--log",
        help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
        default="INFO"
    )
    parser.add_argument(
        "-e", "--export",
        help="Directory to export each artifact to separate text files",
        default=None
    )
    return parser.parse_args()

def main():
    args = parse_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    setup_logging(log_level)
    logging.info("Starting Hunter M DFIR tool (Minimal Version)...")
    
    hunter = HunterM()
    hunter.collect_artifacts()
    
    report = hunter.generate_report(colored=True)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(hunter.generate_report(colored=False))
            logging.info(f"Report written to {args.output}")
        except Exception as e:
            logging.error(f"Failed to write report to file: {e}")
            sys.exit(1)
    else:
        print(report)
    
    if args.export:
        hunter.export_artifacts(args.export)

if __name__ == "__main__":
    main()
