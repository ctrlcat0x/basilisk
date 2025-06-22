import os
import sys
import subprocess
import threading
import tempfile
import time
from typing import List, Optional, Sequence, Union
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup



def run_powershell_script(
    script: str,
    args: Optional[List[str]] = None,
    *,
    monitor_output: bool = False,
    termination_str: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    allow_continue_on_fail: bool = False,
) -> int:
    if not os.path.isabs(script):
        temp_dir = os.environ.get('TEMP', tempfile.gettempdir())
        script_path = os.path.join(temp_dir, 'basilisk', script)
    else:
        script_path = script
    if not os.path.exists(script_path):
        msg = f"PowerShell script not found: {script_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script_path
    ] + (args or [])
    logger.info(f"Launching PowerShell: {' '.join(cmd)}")
    try:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                creationflags |= subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
    except Exception as e:
        logger.exception(f"Failed to start PowerShell process: {e}")
        show_error_popup(
            f"Error launching PowerShell script:\n{e}",
            allow_continue=allow_continue_on_fail,
        )
        raise
    termination_detected = False

    def _stream(pipe, log_fn, label):
        nonlocal termination_detected
        for line in iter(pipe.readline, ""):
            text = line.rstrip()
            log_fn(f"PSCRIPT [{os.path.basename(script_path)}] {label}: {text}")
            if monitor_output and termination_str and termination_str in text:
                logger.info(f"Termination string '{termination_str}' detected.")
                termination_detected = True
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
        pipe.close()
    threads = []
    for pipe, fn, lbl in (
        (proc.stdout, logger.info, "STDOUT"),
        (proc.stderr, logger.error, "STDERR"),
    ):
        t = threading.Thread(target=_stream, args=(pipe, fn, lbl), daemon=True)
        t.start()
        threads.append(t)
    while proc.poll() is None:
        if cancel_event and cancel_event.is_set():
            logger.warning("Killing PowerShell due to external cancellation.")
            try:
                proc.terminate()
            except Exception:
                pass
            break
        time.sleep(0.1)
    for t in threads:
        t.join()
    rc = proc.returncode or 0
    if termination_detected and monitor_output and rc != 0:
        logger.info(
            f"PowerShell terminated after detecting '{termination_str}'. "
            f"Treating exit code {rc} as success."
        )
        rc = 0
    if rc != 0:
        logger.error(f"PowerShell exited with code {rc}")
        show_error_popup(
            f"PowerShell script '{os.path.basename(script_path)}' failed (exit code {rc})",
            allow_continue=allow_continue_on_fail,
        )
        raise RuntimeError(
            f"PowerShell script failed: {script_path} (code {rc})"
        )
    else:
        logger.debug(f"PowerShell completed successfully (code {rc})")
    return rc



def run_powershell_command(
    command: Union[str, Sequence[str]],
    *,
    monitor_output: bool = False,
    termination_str: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    allow_continue_on_fail: bool = False,
) -> int:
    if not isinstance(command, str):
        command = "".join(command)
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ]
    logger.info(f"Launching PowerShell command: {command}")
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags |= subprocess.CREATE_NO_WINDOW
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
    except Exception as e:
        logger.exception(f"Failed to start PowerShell command: {e}")
        show_error_popup(
            f"Error launching PowerShell:\n{e}",
            allow_continue=allow_continue_on_fail,
        )
        raise
    termination_detected = False



    def _stream(pipe, log_fn, label):
        nonlocal termination_detected
        for line in iter(pipe.readline, ""):
            text = line.rstrip()
            log_fn(f"PCOMMAND {label}: {text}")
            if monitor_output and termination_str and termination_str in text:
                logger.info(f"Termination string '{termination_str}' detected.")
                termination_detected = True
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
        pipe.close()
    threads = []
    for pipe, fn, lbl in (
        (proc.stdout, logger.info, "STDOUT"),
        (proc.stderr, logger.error, "STDERR"),
    ):
        t = threading.Thread(target=_stream, args=(pipe, fn, lbl), daemon=True)
        t.start()
        threads.append(t)
    while proc.poll() is None:
        if cancel_event and cancel_event.is_set():
            logger.warning("Killing PowerShell due to external cancellation.")
            try:
                proc.terminate()
            except Exception:
                pass
            break
        time.sleep(0.1)

    for t in threads:
        t.join()
    rc = proc.returncode or 0
    if termination_detected and monitor_output and rc != 0:
        logger.info(
            f"PowerShell terminated after detecting '{termination_str}'. "
            f"Treating exit code {rc} as success."
        )
        rc = 0
    if rc != 0:
        logger.error(f"PowerShell exited with code {rc}")
        show_error_popup(
            f"PowerShell command failed (exit code {rc})",
            allow_continue=allow_continue_on_fail,
        )
        raise RuntimeError(f"PowerShell command failed (code {rc})")
    else:
        logger.debug(f"PowerShell completed successfully (code {rc})")
    return rc