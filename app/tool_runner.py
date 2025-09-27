import subprocess
import logging
import shlex
from typing import List
from app.models import  ToolOutput
import os
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ToolRunner:
    _tool_registry = {}

    @classmethod
    def register_tool(cls, tool_name: str):
        def decorator(func):
            cls._tool_registry[tool_name] = func
            return func
        return decorator

    @classmethod
    def get_command_builder(cls, tool_name: str):
        builder = cls._tool_registry.get(tool_name)
        if not builder:
            raise ValueError(f"Unsupported tool: {tool_name}")
        return builder

    @staticmethod
    def execute_command(command: List[str], scan_id: str, tool_name: str, timeout: int = 3600) -> ToolOutput:
        """
        Safely executes a shell command and captures its output.
        Uses Windows-compatible paths.
        """
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(project_root, "outputs", scan_id, tool_name)
        os.makedirs(output_dir, exist_ok=True)

        base_output_path = os.path.join(output_dir, "output")
        stdout_file = f"{base_output_path}.stdout"
        stderr_file = f"{base_output_path}.stderr"

        cwd = "/opt/recon-ng" if tool_name.lower() == "recon-ng" else None

        try:
            logger.info(f"Executing command: {shlex.join(command)} in directory: {cwd or '/app'}")
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False, check=False, cwd=cwd)

            with open(stdout_file, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
            with open(stderr_file, 'w', encoding='utf-8') as f:
                f.write(result.stderr)

            expected_output_file = None
            try:
                output_flags = ['-o', '-oA', '-oG', '-oJ', '-oN', '-oX', '-f', '--log-brief']
                for i, part in enumerate(command):
                    if part in output_flags and i + 1 < len(command):
                        expected_output_file = command[i + 1]
                        break
            except Exception:
                pass

            if expected_output_file and not os.path.exists(expected_output_file) and result.stdout:
                try:
                    os.makedirs(os.path.dirname(expected_output_file), exist_ok=True)
                    with open(expected_output_file, 'w', encoding='utf-8') as f:
                        f.write(result.stdout)
                    logger.info(f"Created fallback output file at {expected_output_file}")
                except Exception as e:
                    logger.error(f"Could not create fallback output file: {e}")

            stderr_lower = (result.stderr or "").lower()
            stdout_lower = (result.stdout or "").lower()
            
            success = False
            tool_name_lower = tool_name.lower()

            if tool_name_lower in ['recon-ng', 'dirsearch', 'theharvester']:
                if result.returncode == 0 and 'error' not in (result.stderr or "").lower() and 'traceback' not in (result.stderr or "").lower():
                    success = True
            elif tool_name_lower == 'dnsenum':
                stderr_lower = (result.stderr or "").lower()
                stdout_lower = (result.stdout or "").lower()

                benign_errors = ["query failed", "noerror", "lame server"]

                has_benign_error = any(err in stderr_lower for err in benign_errors)

                if 'can\'t locate' not in stderr_lower:
                    if result.returncode == 0:
                        success = True
                    elif result.returncode != 0 and has_benign_error:
                        # Allow partial success if dnsenum gave output but only benign errors
                        success = True

            else:
                stderr_lower = (result.stderr or "").lower()
                stdout_lower = (result.stdout or "").lower()
                error_markers = ["invalid module", "invalid option", "invalid command", "error", "traceback", "no such file", "not found", "[!]", "fail", "module not found"]
                found_error = any(marker in stdout_lower for marker in error_markers) or any(marker in stderr_lower for marker in error_markers)
                success = (result.returncode == 0) and not found_error


            output_files = [stdout_file, stderr_file]
            
            for filename in os.listdir(output_dir):
                if filename not in ["output.stdout", "output.stderr"]:
                    full_path = os.path.join(output_dir, filename)
                    if os.path.isfile(full_path):
                        output_files.append(full_path)

            return ToolOutput(
                tool_name=tool_name,
                command=command,
                return_code=result.returncode,
                stdout=result.stdout[-2000:],
                stderr=result.stderr[-2000:],
                output_file_paths=output_files,
                success=success
            )

        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds."
            logger.error(error_msg)
            with open(stderr_file, 'w') as f:
                f.write(error_msg)
            return ToolOutput(
                tool_name=tool_name, command=command, return_code=-1, stdout="",
                stderr=error_msg, output_file_paths=[stderr_file], success=False
            )
        except Exception as e:
            error_msg = f"Failed to execute command: {str(e)}"
            logger.exception(error_msg)
            return ToolOutput(
                tool_name=tool_name, command=command, return_code=-1, stdout="",
                stderr=error_msg, output_file_paths=[], success=False
            )
            
            
# --- Tool Command Builders ---
@ToolRunner.register_tool("nmap")
def build_nmap_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds nmap command with proper parameter handling for Windows.
    Handles both ToolParameter objects and dictionaries.
    """    
    cmd = ["nmap"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    output_base = os.path.join(output_dir, "nmap_scan")
    output_specified = False
        
    for param in parameters:
        if hasattr(param, 'flag'):
            flag = param.flag
            value = param.value
            requires_value = getattr(param, 'requiresValue', False)
        else:
            flag = param.get('flag')
            value = param.get('value')
            requires_value = param.get('requiresValue', False)
        if not flag or flag == "<target>": continue            
        if flag in ('-oX', '-oN', '-oA'):
            output_specified = True
            cmd.extend([flag, output_base])
        elif requires_value and value is not None: cmd.extend([flag, str(value)])
        elif not requires_value and value in (True, "true"): cmd.append(flag)

    if not output_specified:
        cmd.extend(["-oX", f"{output_base}.xml"])
    
    cmd.append(target)
    
    logger.info(f"Built nmap command: {cmd}")
    return cmd

@ToolRunner.register_tool("masscan")
def build_masscan_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds masscan command with proper parameter handling.
    """
    cmd = ["masscan"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    output_base = os.path.join(output_dir, "masscan_scan.json")

    ports_specified = any(p.flag in ('-p', '--ports') for p in parameters if hasattr(p, 'flag')) or any(p.get('flag') in ('-p', '--ports') for p in parameters if isinstance(p, dict))
    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')
        if value is not None and value not in (True, "true"):
            cmd.extend([flag, str(value)])
        elif value in (True, "true"):
            cmd.append(flag)
    
    if not ports_specified:
        cmd.extend(["-p", "1-1000"])
        
    cmd.extend(["-oJ", output_base])
    print("Target in masscan: ", target)
    cmd.append(target)
    logger.info(f"Built masscan command: {cmd}")
    return cmd

@ToolRunner.register_tool("amass")
def build_amass_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds amass command with proper parameter handling.
    -rf flag is a boolean that points to a hardcoded wordlist.
    Ignores deprecated flags like -src and -ip.
    """
    cmd = ["amass", "enum", "-d", target]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    wordlists_dir = "/app/wordlists"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "amass_scan.txt")

    
    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value, requires_value = param.flag, param.value, getattr(param, 'requiresValue', False)
        else:
            flag, value, requires_value = param.get('flag'), param.get('value'), param.get('requiresValue', False)

        if not flag or flag in ["enum", "intel", "-src", "-ip"]: 
            continue

        if flag == "-rf" and value in (True, "true"):
            cmd.extend(["-rf", os.path.join(wordlists_dir, "subdomains-top1million-5000.txt")])
        elif flag not in ["-d", "enum"]:
            if value is not None and value not in (True, "true"): cmd.extend([flag, str(value)])
            elif value in (True, "true"): cmd.append(flag)

    
    cmd.extend(["-o", output_file])
    logger.info(f"Built amass command: {cmd}")
    return cmd

@ToolRunner.register_tool("subfinder")
def build_subfinder_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds subfinder command with proper parameter handling.
    -dL flag is a boolean that points to a hardcoded domain list.
    """
    cmd = ["subfinder", "-silent"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    target_lists_dir = "/app/target_lists"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "subfinder_scan.json")
    
    domain_flag_used = False

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value, requires_value = param.flag, param.value, getattr(param, 'requiresValue', False)
        else:
            flag, value, requires_value = param.get('flag'), param.get('value'), param.get('requiresValue', False)        
        if flag == "-dL" and value in (True, "true"):
            cmd.extend(["-dL", os.path.join(target_lists_dir, "domains.txt")])
            domain_flag_used = True
            break

    if not domain_flag_used:
        cmd.extend(["-d", target])

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value, getattr(param, 'requiresValue', False)
        else:
            flag, value = param.get('flag'), param.get('value'), param.get('requiresValue', False)

        if flag not in ["-d", "-dL", "-silent"]:
             if value is not None and value not in (True, "true"): 
                 cmd.extend([flag, str(value)])
             elif value in (True, "true"): 
                 cmd.append(flag)


    cmd.extend(["-oJ", output_file])
    logger.info(f"Built subfinder command: {cmd}")
    return cmd

@ToolRunner.register_tool("theharvester")
def build_theharvester_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds theHarvester command with proper parameter handling.
    """
    cmd = ["theharvester", "-d", target]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "theharvester_scan.html")

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')

        if flag not in ["-d", "-f"]:
            if value is not None and value not in (True, "true"): cmd.extend([flag, str(value)])
            elif value in (True, "true"): cmd.append(flag)

    cmd.extend(["-f", output_file])
    logger.info(f"Built theHarvester command: {cmd}")
    return cmd

@ToolRunner.register_tool("recon-ng")
def build_recon_ng_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds a recon-ng command by dynamically creating a resource script.
    """
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    template_path = "/app/scripts/templates/recon_ng_template.rc"
    temp_script_path = os.path.join(output_dir, "workflow.rc")
    output_report_path = os.path.join(output_dir, "report.html")

    workspace = f"{target.replace('.', '_')}_{scan_id}"
    
    for param in parameters:
        flag = param.flag if hasattr(param, 'flag') else param.get('flag')
        value = param.value if hasattr(param, 'value') else param.get('value')
        if flag == '--workspace' and value:
            workspace = value
            break
    
    try:
        with open(template_path, 'r') as f:
            template_content = f.read()


        script_content = template_content.replace("{{ workspace }}", workspace)
        script_content = script_content.replace("{{ domain }}", target)
        script_content = script_content.replace("{{ output_file }}", output_report_path)
        
        with open(temp_script_path, 'w') as f:
            f.write(script_content)

    except FileNotFoundError:
        raise ValueError("Recon-ng template file not found.")
    except Exception as e:
        raise ValueError(f"Failed to create recon-ng script: {e}")

    cmd = ["recon-ng", "-r", temp_script_path]
    logger.info(f"Built recon-ng command: {cmd}")
    return cmd

@ToolRunner.register_tool("gobuster")
def build_gobuster_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    cmd = ["gobuster"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    wordlists_dir = "/app/wordlists"
    os.makedirs(output_dir, exist_ok=True)
    output_base = os.path.join(output_dir, "gobuster_scan")

    mode = next((param.value for param in parameters if (hasattr(param, 'flag') and param.flag == "mode") or (isinstance(param, dict) and param.get('flag') == "mode")), None)
    cmd.append(mode)

    target_flag_set = False
    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')       
        if not flag or flag == "mode": continue

        if flag == "-w":
            if value in (True, "true"):
                cmd.extend([flag, os.path.join(wordlists_dir, "common.txt")])
            continue
            
        if flag == "-o":
            cmd.extend([flag, f"{output_base}.txt"])
            continue

        if flag == "-u" or flag == "-d":
            target_flag_set = True
            # For dir/vhost, ensure it's a full URL
            if mode in ['dir', 'vhost']:
                url = value if value else target
                if not url.startswith(('http://', 'https://')):
                    url = f"http://{url}"
                cmd.extend(['-u', url])
            # For dns, use the domain directly
            else:
                cmd.extend(['-d', value if value else target])
            continue

        if value is not None and str(value).lower() not in ('true', '1', ''):
            cmd.extend([flag, str(value)])
        elif value in (True, "true"):
            cmd.append(flag)
    
    if not target_flag_set:
        if mode in ['dir', 'vhost']:
            url = target
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            cmd.extend(['-u', url])
        elif mode == 'dns':
            cmd.extend(['-d', target])

    if mode in ["dir", "vhost"] and "-w" not in cmd:
        cmd.extend(["-w", os.path.join(wordlists_dir, "common.txt")])
            
    if "-o" not in cmd:
        cmd.extend(["-o", f"{output_base}.txt"])

    logger.info(f"Built gobuster command: {cmd}")
    return cmd

@ToolRunner.register_tool("dirsearch")
def build_dirsearch_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    cmd = ["dirsearch"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    wordlists_dir = "/app/wordlists"
    os.makedirs(output_dir, exist_ok=True)
    output_base = os.path.join(output_dir, "dirsearch_scan")
    target_flag_set = False

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')               
        if not flag: continue

        if flag == "-w":
            if value in (True, "true"):
                cmd.extend([flag, os.path.join(wordlists_dir, "directory-list-2.3-small.txt")])
            continue
            
        if flag == "-o":
            cmd.extend([flag, f"{output_base}.txt"])
            continue
            
        if flag == "-u":
            url = value if value else target
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            cmd.extend([flag, url])
            target_flag_set = True
            continue

        if value is not None and str(value).lower() not in ('true', '1', ''):
            cmd.extend([flag, str(value)])
        elif value in (True, "true"):
            cmd.append(flag)

    if not target_flag_set:
        url = target
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        cmd.extend(['-u', url])

    if "-w" not in cmd:
        cmd.extend(["-w", os.path.join(wordlists_dir, "directory-list-2.3-small.txt")])
            
    if "-o" not in cmd:
        cmd.extend(["-o", f"{output_base}.txt"])

    logger.info(f"Built dirsearch command: {cmd}")
    return cmd

@ToolRunner.register_tool("whatweb")
def build_whatweb_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    cmd = ["whatweb"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    output_base = os.path.join(output_dir, "whatweb_scan")
    output_specified = False

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')       
        if not flag or flag == "<target>": continue

        if flag == "--log-brief":
            cmd.extend([flag, f"{output_base}.txt"])
            output_specified = True
            continue
            
        if value is not None and str(value).lower() not in ('true', '1', ''):
            cmd.extend([flag, str(value)])
        elif value in (True, "true"):
            cmd.append(flag)
    
    if not output_specified:
        cmd.extend(["--log-brief", f"{output_base}.txt"])

    url = target
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    cmd.append(url)

    logger.info(f"Built whatweb command: {cmd}")
    return cmd


@ToolRunner.register_tool("dnsenum")
def build_dnsenum_command(target: str, parameters: List, scan_id: str, tool_name: str) -> List[str]:
    """
    Builds dnsenum command with proper parameter handling.
    --file is a boolean that points to a hardcoded wordlist.
    Domain is always the main target.
    """
    cmd = ["dnsenum"]
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    wordlists_dir = "/app/wordlists"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "dnsenum_scan.xml") # dnsenum can output xml

    for param in parameters:
        if hasattr(param, 'flag'):
            flag, value = param.flag, param.value
        else:
            flag, value = param.get('flag'), param.get('value')       
        
        if not flag:
            continue
        
        # Check for the logical '--file' flag from the frontend
        if flag == "--file" and value in (True, "true", "True"):
            cmd.extend(["-f", os.path.join(wordlists_dir, "subdomains-top1million-5000.txt")])
        elif flag not in ["-o", "--file", "<domain>"]:
            if value is not None and value not in (True, "true", "True"):
                cmd.extend([flag, str(value)])
            elif value in (True, "true", "True"):
                cmd.append(flag)

    cmd.extend(["-o", output_file])
    # Append the target domain at the very end, after all options
    cmd.append(target)
    logger.info(f"Built dnsenum command: {cmd}")
    return cmd


