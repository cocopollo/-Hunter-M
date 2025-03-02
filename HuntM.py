#!/usr/bin/env python3
"""
Hunter M -  macOS Artifacts
--------------------------------------------------------------
This tool collects a comprehensive set of forensic artifacts:
  - Login Items
  - Network Connections
  - Extended Zsh History
  - Running Processes
  - Browser History (Safari, Chrome, Firefox)
  - Installed Applications

A professional banner "Hunter M" is displayed at the top of the report.

Copyright (c) 2025 [MahmoudSwelam]
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
        self.artifacts = {
            "login_items": [],
            "network_connections": [],
            "zsh_history": [],
            "running_processes": [],
            "browser_history": [],
            "installed_apps": [],
        }

    def collect_artifacts(self):
        logging.info("Collecting forensic artifacts...")
        self.artifacts["login_items"] = self.get_login_items()
        self.artifacts["network_connections"] = self.get_network_connections()
        self.artifacts["zsh_history"] = self.get_zsh_history_extended()
        self.artifacts["running_processes"] = self.get_running_processes()
        self.artifacts["browser_history"] = self.get_browser_history()
        self.artifacts["installed_apps"] = self.get_installed_apps()

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

    def get_browser_history(self, browser="safari"):
        history_paths = {
            "safari": os.path.expanduser("~/Library/Safari/History.db"),
            "chrome": os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History"),
            "firefox": os.path.expanduser("~/Library/Application Support/Firefox/Profiles/*/places.sqlite"),
        }
        history = []
        if browser in history_paths:
            path = history_paths[browser]
            if os.path.exists(path):
                try:
                    import sqlite3, tempfile, shutil
                    # For Safari, copy the locked database to a temporary file.
                    if browser == "safari":
                        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
                        os.close(tmp_fd)
                        shutil.copy2(path, tmp_path)
                        db_path = tmp_path
                    else:
                        db_path = path
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                    for row in cursor.fetchall():
                        history.append(f"URL: {row[0]}, Title: {row[1]}, Last Visited: {row[2]}")
                    conn.close()
                    if browser == "safari":
                        os.remove(tmp_path)
                except Exception as e:
                    logging.error(f"Error reading {browser} history: {e}")
            else:
                logging.warning(f"{browser} history file not found at {path}")
        return history

    def get_installed_apps(self):
        logging.debug("Retrieving installed applications using system_profiler...")
        apps = []
        try:
            output = subprocess.check_output(["system_profiler", "SPApplicationsDataType"], universal_newlines=True)
            apps = output.splitlines()
        except Exception as e:
            logging.error(f"Error retrieving installed applications: {e}")
        return apps

    def generate_banner(self, colored=True):
        banner = r"""
    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝
    """
        version = "v1.0.0"
        description = "macOS DFIR Artifact Collection and Analysis Tool"
        if colored and COLORAMA_AVAILABLE:
            banner = Fore.GREEN + banner + Style.RESET_ALL
            version = Fore.CYAN + version + Style.RESET_ALL
            description = Fore.YELLOW + description + Style.RESET_ALL
        return f"{banner}\n{version}\n{description}\n"

    def generate_report(self, colored=True):
        sections = []
        sections.append(self.generate_banner(colored))
        header_line = "=" * 50
        if colored and COLORAMA_AVAILABLE:
            header = Fore.CYAN + header_line + Style.RESET_ALL
        else:
            header = header_line
        sections.append(header)

        # Artifact categories to include.
        categories = [
            ("Login Items", "login_items"),
            ("Network Connections", "network_connections"),
            ("Zsh History (Extended)", "zsh_history"),
            ("Running Processes", "running_processes"),
            ("Browser History", "browser_history"),
            ("Installed Applications", "installed_apps"),
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
        sections.append(header)
        return "\n".join(sections)

    def export_artifacts(self, export_dir):
        """Export each artifact category into separate, well-formatted text files."""
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
        
        for key, items in self.artifacts.items():
            filename = os.path.join(export_dir, f"{key}.txt")
            try:
                with open(filename, "w") as f:
                    if items:
                        # Add a header for each artifact category.
                        f.write(f"=== {key.replace('_', ' ').title()} ===\n\n")
                        
                        if key == "login_items":
                            f.write("Login items are applications or scripts that start automatically when the user logs in.\n\n")
                            for item in items:
                                f.write(f"- {item}\n")
                        
                        elif key == "network_connections":
                            f.write("Active network connections (ESTABLISHED state).\n\n")
                            for item in items:
                                f.write(f"{item}\n")
                        
                        elif key == "zsh_history":
                            f.write("Extended Zsh command history with timestamps and session details.\n\n")
                            for item in items:
                                f.write(f"{item}\n")
                        
                        elif key == "running_processes":
                            f.write("List of currently running processes.\n\n")
                            for item in items:
                                f.write(f"- {item}\n")
                        
                        elif key == "browser_history":
                            f.write("Browser history (URLs, titles, and last visited timestamps).\n\n")
                            for item in items:
                                f.write(f"{item}\n")
                        
                        elif key == "installed_apps":
                            f.write("List of installed applications.\n\n")
                            for item in items:
                                f.write(f"- {item}\n")
                        
                        f.write("\n")
                    else:
                        f.write("[No data found]\n")
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
        description="Hunter M: A macOS DFIR Artifact Collection and Analysis Tool",
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
    
    # Immediately display the banner to show the tool is working.
    hunter = HunterM()
    print(hunter.generate_banner(colored=True))
    
    logging.info("Starting Hunter M DFIR tool...")
    hunter.collect_artifacts()

    # If the export flag is provided, export artifacts only (do not print the report or write to output file).
    if args.export:
        hunter.export_artifacts(args.export)
        logging.info(f"Artifacts exported to directory: {args.export}")
    else:
        report = hunter.generate_report(colored=True)
        if args.output:
            try:
                with open(args.output, "w") as f:
                    # Write a non-colored report to file.
                    f.write(hunter.generate_report(colored=False))
                logging.info(f"Report written to {args.output}")
            except Exception as e:
                logging.error(f"Failed to write report to file: {e}")
                sys.exit(1)
        else:
            print(report)


if __name__ == "__main__":
    main()
