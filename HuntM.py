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
import shutil
import tempfile
import sqlite3
import time
import pathlib
import json
from contextlib import contextmanager

# Optional: Use colorama for colorful terminal output.
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class HunterM:
    """Hunter M - macOS forensic artifact collection tool."""
    
    # Default subprocess timeout in seconds
    SUBPROCESS_TIMEOUT = 30
    
    def __init__(self):
        """Initialize the artifact collection tool."""
        self.artifacts = {
            "login_items": [],
            "network_connections": [],
            "zsh_history": [],
            "running_processes": [],
            "browser_history": [],
            "installed_apps": [],
        }
        # Store user consent for browser history collection
        self.collect_browser_history = False

    def collect_artifacts(self):
        """Collect all forensic artifacts."""
        logging.info("Collecting forensic artifacts...")
        self.artifacts["login_items"] = self.get_login_items()
        self.artifacts["network_connections"] = self.get_network_connections()
        self.artifacts["zsh_history"] = self.get_zsh_history_extended()
        self.artifacts["running_processes"] = self.get_running_processes()
        if self.collect_browser_history:
            self.artifacts["browser_history"] = self.get_browser_history()
        self.artifacts["installed_apps"] = self.get_installed_apps()

    def get_login_items(self):
        """Retrieve login items using osascript."""
        logging.debug("Retrieving login items using osascript...")
        try:
            output = self._run_subprocess(
                ["osascript", "-e", 'tell application "System Events" to get the name of every login item']
            )
            return [item.strip() for item in output.split(",") if item.strip()]
        except subprocess.SubprocessError as e:
            logging.error("Error retrieving login items: %s", str(e))
            return []
        except Exception as e:
            logging.error("Unexpected error retrieving login items: %s", str(e))
            return []

    def get_network_connections(self):
        """Retrieve active network connections."""
        logging.debug("Retrieving network connections using lsof...")
        connections = []
        try:
            output = self._run_subprocess(["lsof", "-i", "-n", "-P"])
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
                            ps_out = self._run_subprocess(["ps", "-p", pid, "-o", "lstart="]).strip()
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
        except subprocess.SubprocessError as e:
            logging.error("Error retrieving network connections: %s", str(e))
            return []
        except Exception as e:
            logging.error("Unexpected error retrieving network connections: %s", str(e))
            return []

    def get_zsh_history_extended(self):
        """Retrieve extended zsh history with timestamps."""
        logging.debug("Retrieving extended zsh history...")
        home = os.path.expanduser("~")
        path = os.path.join(home, ".zsh_history")
        results = []
        username = os.getenv("USER", "unknown")
        pattern = re.compile(r"^:\s*(\d+):\d+;(.*)$")
        current_sudo_session = None
        cmd_index = 0
        
        if not os.path.exists(path):
            logging.warning("zsh history file not found at %s", path)
            return []
            
        try:
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()
                
            for line in lines:
                cmd_index += 1
                line = line.strip()
                # Skip empty lines
                if not line:
                    continue
                    
                # Sanitize potentially sensitive data
                match = pattern.match(line)
                if match:
                    ts = int(match.group(1))
                    command = self._sanitize_command(match.group(2).strip())
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
                    sanitized_line = self._sanitize_command(line)
                    results.append(f"Cmd #{cmd_index}: {sanitized_line}")
            return results
        except PermissionError:
            logging.error("Permission denied reading zsh history")
            return []
        except Exception as e:
            logging.error("Error reading zsh history: %s", type(e).__name__)
            return []

    def _sanitize_command(self, command):
        """Sanitize potentially sensitive commands by removing tokens, passwords, etc."""
        # Remove potential passwords, tokens, and keys
        sanitized = re.sub(r'(-p|--password=?|token=?|key=?|secret=?)\s*[^\s]*', r'\1 [REDACTED]', command)
        # Redact AWS keys and other sensitive patterns
        sanitized = re.sub(r'(AWS_SECRET_ACCESS_KEY=)[\w\/+]+', r'\1[REDACTED]', sanitized)
        sanitized = re.sub(r'(AWS_ACCESS_KEY_ID=)[\w]+', r'\1[REDACTED]', sanitized)
        return sanitized

    def get_running_processes(self):
        """Retrieve list of running processes."""
        logging.debug("Retrieving running processes using ps aux...")
        try:
            output = self._run_subprocess(["ps", "aux"])
            lines = output.splitlines()[1:]
            procs = []
            for line in lines:
                parts = line.split()
                if len(parts) > 10:
                    procs.append(parts[10])
            return sorted(set(procs))
        except subprocess.SubprocessError as e:
            logging.error("Error retrieving running processes: %s", str(e))
            return []
        except Exception as e:
            logging.error("Unexpected error retrieving processes: %s", str(e))
            return []

    def get_browser_history(self):
        """Retrieve browser history from Safari, Chrome, and Firefox."""
        history = []
        
        # Skip if user hasn't consented
        if not self.collect_browser_history:
            logging.info("Browser history collection skipped (no user consent)")
            return []
            
        # Define browser database paths
        history_paths = {
            "safari": os.path.expanduser("~/Library/Safari/History.db"),
            "chrome": os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History"),
            "firefox": os.path.expanduser("~/Library/Application Support/Firefox/Profiles/"),
        }
        
        # Collect history from each browser
        for browser, path in history_paths.items():
            if browser == "firefox":
                # Handle Firefox's multiple profile directories
                if os.path.exists(path):
                    try:
                        for profile_dir in os.listdir(path):
                            profile_path = os.path.join(path, profile_dir, "places.sqlite")
                            if os.path.exists(profile_path):
                                history.extend(self._extract_browser_history(browser, profile_path))
                    except Exception as e:
                        logging.error("Error processing Firefox profiles: %s", type(e).__name__)
            else:
                # Handle Safari and Chrome
                if os.path.exists(path):
                    history.extend(self._extract_browser_history(browser, path))
                    
        return history

    def _extract_browser_history(self, browser, db_path):
        """Extract history from a browser database safely."""
        history_items = []
        logging.debug("Extracting %s history from %s", browser, db_path)
        
        try:
            # Create a temporary copy of the database to avoid locking issues
            with self._temp_copy(db_path) as temp_db:
                # Different queries depending on browser type
                if browser == "safari":
                    query = "SELECT url, title, datetime(visit_time + 978307200, 'unixepoch') as last_visit FROM history_visits JOIN history_items ON history_items.id = history_visits.history_item ORDER BY visit_time DESC LIMIT 100"
                elif browser == "chrome":
                    query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') as last_visit FROM urls ORDER BY last_visit_time DESC LIMIT 100"
                elif browser == "firefox":
                    query = "SELECT url, title, datetime(visit_date/1000000, 'unixepoch') as last_visit FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY visit_date DESC LIMIT 100"
                else:
                    return []
                
                # Connect to database and execute query
                with self._database_connection(temp_db) as cursor:
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        url = row[0]
                        title = row[1] if row[1] else "(No Title)"
                        last_visited = row[2]
                        history_items.append(f"[{browser.title()}] URL: {url}, Title: {title}, Last Visited: {last_visited}")
                
        except sqlite3.Error as e:
            logging.error("SQLite error reading %s history: %s", browser, type(e).__name__)
        except Exception as e:
            logging.error("Error reading %s history: %s", browser, type(e).__name__)
            
        return history_items

    @contextmanager
    def _temp_copy(self, file_path):
        """Create a temporary copy of a file and clean up afterward."""
        temp_fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(file_path)[1])
        try:
            os.close(temp_fd)
            shutil.copy2(file_path, temp_path)
            yield temp_path
        finally:
            try:
                # Secure deletion of temporary file
                if os.path.exists(temp_path):
                    with open(temp_path, 'wb') as f:
                        f.write(b'\0' * os.path.getsize(temp_path))
                    os.unlink(temp_path)
            except Exception as e:
                logging.warning("Failed to securely delete temporary file: %s", type(e).__name__)

    @contextmanager
    def _database_connection(self, db_path):
        """Create a database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            yield cursor
        except sqlite3.Error as e:
            logging.error("Database error: %s", type(e).__name__)
            raise
        finally:
            if conn:
                conn.close()

    def get_installed_apps(self):
        """Retrieve list of installed applications."""
        logging.debug("Retrieving installed applications using system_profiler...")
        apps = []
        try:
            output = self._run_subprocess(["system_profiler", "SPApplicationsDataType"])
            apps = output.splitlines()
        except subprocess.SubprocessError as e:
            logging.error("Error retrieving installed applications: %s", str(e))
        except Exception as e:
            logging.error("Unexpected error retrieving applications: %s", str(e))
        return apps

    def _run_subprocess(self, cmd, timeout=SUBPROCESS_TIMEOUT):
        """Run a subprocess with timeout and proper error handling."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logging.error("Command timed out after %s seconds: %s", timeout, " ".join(cmd))
            raise
        except subprocess.CalledProcessError as e:
            logging.error("Command returned non-zero exit status: %s", " ".join(cmd))
            if e.stderr:
                logging.debug("Command stderr: %s", e.stderr)
            raise
        except Exception as e:
            logging.error("Error executing command: %s, error: %s", " ".join(cmd), type(e).__name__)
            raise

    def generate_banner(self, colored=True):
        """Generate the tool banner."""
        banner = r"""
    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝
    """
        version = "v1.0.1"
        description = "macOS DFIR Artifact Collection and Analysis Tool"
        if colored and COLORAMA_AVAILABLE:
            banner = Fore.GREEN + banner + Style.RESET_ALL
            version = Fore.CYAN + version + Style.RESET_ALL
            description = Fore.YELLOW + description + Style.RESET_ALL
        return f"{banner}\n{version}\n{description}\n"

    def generate_report(self, colored=True):
        """Generate the complete artifact report."""
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
            if key == "browser_history" and not self.collect_browser_history:
                continue
                
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
        # Validate and sanitize export directory path
        try:
            export_path = pathlib.Path(export_dir).resolve()
            # Ensure the path doesn't escape to a sensitive location
            if not str(export_path).startswith(os.getcwd()):
                logging.warning("Export path must be within the current working directory")
                export_path = pathlib.Path(os.path.join(os.getcwd(), "hunter_output"))
                logging.info("Using safe default path: %s", export_path)
                
            # Create directory with secure permissions
            export_path.mkdir(parents=True, exist_ok=True)
            # Set directory permissions to owner-only (0o700)
            os.chmod(export_path, 0o700)
        except Exception as e:
            logging.error("Failed to create export directory: %s", type(e).__name__)
            return
        
        # Export each artifact category
        for key, items in self.artifacts.items():
            # Skip browser history if not authorized
            if key == "browser_history" and not self.collect_browser_history:
                continue
                
            try:
                # Create safe filename
                safe_filename = self._safe_filename(key)
                filename = os.path.join(export_path, f"{safe_filename}.txt")
                
                with open(filename, "w") as f:
                    if items:
                        # Add a header for each artifact category
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
                
                # Set secure file permissions (0o600 - owner read/write only)
                os.chmod(filename, 0o600)
                logging.info("Exported %s to %s", key, filename)
                
            except PermissionError:
                logging.error("Permission denied when exporting %s", key)
            except Exception as e:
                logging.error("Error exporting %s: %s", key, type(e).__name__)

    def _safe_filename(self, filename):
        """Create a safe filename by removing potentially unsafe characters."""
        # Remove any non-alphanumeric characters except underscores
        return re.sub(r'[^\w\-_]', '', filename)

    def export_summary(self, export_dir):
        """Export a summary file with metadata about the collection."""
        try:
            # Create a safe export directory path
            export_path = pathlib.Path(export_dir).resolve()
            summary_file = os.path.join(export_path, "collection_summary.json")
            
            # Gather metadata
            summary = {
                "collection_time": datetime.datetime.now().isoformat(),
                "hostname": os.uname().nodename,
                "os_version": self._run_subprocess(["sw_vers", "-productVersion"]).strip(),
                "user": os.getenv("USER", "unknown"),
                "artifact_types": list(self.artifacts.keys()),
                "artifact_counts": {k: len(v) for k, v in self.artifacts.items()},
            }
            
            # Write summary file
            with open(summary_file, "w") as f:
                json.dump(summary, f, indent=2)
                
            # Set secure permissions
            os.chmod(summary_file, 0o600)
            logging.info("Exported collection summary to %s", summary_file)
            
        except Exception as e:
            logging.error("Error exporting collection summary: %s", type(e).__name__)


def setup_logging(level=logging.INFO):
    """Configure logging with appropriate format and level."""
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Create log directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Set up file handler for logging
        log_file = os.path.join(log_dir, f"hunterm_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        
        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format, date_format))
        
        # Configure root logger
        logging.basicConfig(
            level=level,
            format=log_format,
            datefmt=date_format,
            handlers=[file_handler, console_handler]
        )
        
        # Set permissions on log file
        os.chmod(log_file, 0o600)
        
    except Exception as e:
        # Fallback to basic logging if setting up file logging fails
        logging.basicConfig(
            level=level,
            format=log_format,
            datefmt=date_format
        )
        logging.warning("Failed to set up file logging: %s", str(e))


def parse_args():
    """Parse command line arguments."""
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
    parser.add_argument(
        "-b", "--browser-history",
        help="Collect browser history (requires explicit consent)",
        action="store_true"
    )
    parser.add_argument(
        "--no-color",
        help="Disable colored output",
        action="store_true"
    )
    parser.add_argument(
        "--timeout",
        help="Subprocess timeout in seconds (default: 30)",
        type=int,
        default=30
    )
    return parser.parse_args()


def check_root():
    """Check if the tool is running with root privileges."""
    if os.geteuid() == 0:
        logging.warning("Running with root privileges - this is not recommended for security reasons")
        return True
    return False


def main():
    """Main entry point for the Hunter M tool."""
    # Parse command line arguments
    args = parse_args()
    
    # Set up logging
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    setup_logging(log_level)
    
    # Check for root privileges
    is_root = check_root()
    
    # Update subprocess timeout
    HunterM.SUBPROCESS_TIMEOUT = args.timeout
    
    # Create and configure the Hunter M instance
    hunter = HunterM()
    
    # Set browser history collection flag based on user consent
    hunter.collect_browser_history = args.browser_history
    if args.browser_history:
        logging.info("Browser history collection enabled by user consent")
    
    # Display the banner
    use_color = COLORAMA_AVAILABLE and not args.no_color
    print(hunter.generate_banner(colored=use_color))
    
    # Start collection
    logging.info("Starting Hunter M DFIR tool (v1.0.1)...")
    hunter.collect_artifacts()

    # Export artifacts if requested
    if args.export:
        try:
            # Validate export path
            export_dir = os.path.abspath(args.export)
            
            # Export artifacts and summary
            hunter.export_artifacts(export_dir)
            hunter.export_summary(export_dir)
            
            logging.info("Artifacts exported to directory: %s", export_dir)
            
        except Exception as e:
            logging.error("Failed to export artifacts: %s", type(e).__name__)
    
    # Generate and display/save report
    if not args.export or args.output:
        report = hunter.generate_report(colored=use_color)
        if args.output:
            try:
                # Validate output path
                output_path = os.path.abspath(args.output)
                
                # Write report to file (non-colored)
                with open(output_path, "w") as f:
                    f.write(hunter.generate_report(colored=False))
                
                # Set secure permissions
                os.chmod(output_path, 0o600)
                logging.info("Report written to %s", output_path)
                
            except PermissionError:
                logging.error("Permission denied when writing report")
                sys.exit(1)
            except Exception as e:
                logging.error("Failed to write report: %s", type(e).__name__)
                sys.exit(1)
        else:
            print(report)

    logging.info("Hunter M execution completed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        logging.info("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.critical("Unhandled exception: %s", type(e).__name__)
        sys.exit(1)
