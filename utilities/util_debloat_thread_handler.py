import sys
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup



class ScriptProcessHandler:

    def __init__(self, max_workers: int = None, stop_on_error: bool = True):
        self.scripts = []
        self.max_workers = max_workers
        self.stop_on_error = stop_on_error
        self._cancel_event = threading.Event()
        self._processes = []
        self._lock = threading.Lock()

    def add_script(self, script_path: str):
        self.scripts.append(script_path)

    def run_all(self):
        total = len(self.scripts)
        workers = self.max_workers or total or 1
        logger.info(f"Starting execution of {total} scripts with up to {workers} workers")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._run_script, path): path for path in self.scripts}
            try:
                for future in as_completed(futures):
                    script = futures[future]
                    future.result()
                    logger.info(f"✔ Script succeeded: {script}")
            except Exception as e:
                logger.error(f"✖ Failure in script '{script}': {e}")
                if self.stop_on_error:
                    logger.info("Cancelling remaining scripts...")
                    self._cancel_event.set()
                    self._terminate_all_processes()
                raise
        if self._cancel_event.is_set():
            raise RuntimeError("Execution aborted due to earlier error")

    def _run_script(self, script_path: str):
        if self._cancel_event.is_set():
            logger.warning(f"Skipping {script_path} (cancelled)")
            return
        logger.info(f"Launching script: {script_path}")
        cmd = [sys.executable, script_path]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except Exception as e:
            logger.exception(f"Failed to start process for {script_path}: {e}")
            raise
        with self._lock:
            self._processes.append(proc)
        def _log_stream(pipe, log_fn, prefix):
            for line in iter(pipe.readline, ''):
                log_fn(f"{script_path} {prefix}: {line.rstrip()}")
            pipe.close()
        out_thread = threading.Thread(
            target=_log_stream, args=(proc.stdout, logger.info, "STDOUT"), daemon=True
        )
        err_thread = threading.Thread(
            target=_log_stream, args=(proc.stderr, logger.error, "STDERR"), daemon=True
        )
        out_thread.start()
        err_thread.start()
        while proc.poll() is None:
            if self._cancel_event.is_set():
                logger.warning(
                    f"Terminating script due to cancellation: {script_path} (pid={proc.pid})"
                )
                proc.terminate()
                break
        out_thread.join()
        err_thread.join()
        returncode = proc.returncode or 0
        if returncode != 0:
            logger.error(f"{script_path} exited with code {returncode}")
            show_error_popup(f"Script '{script_path}' failed with exit code {returncode}", allow_continue=False)
            raise RuntimeError(f"{script_path} failed (exit code {returncode})")

    def _terminate_all_processes(self):
        with self._lock:
            for proc in self._processes:
                if proc.poll() is None:
                    try:
                        logger.warning(f"Force-killing process pid={proc.pid}")
                        proc.terminate()
                    except Exception as e:
                        logger.error(f"Error terminating pid={proc.pid}: {e}")



def run_scripts_threaded(script_paths: list, max_workers: int = None):
    handler = ScriptProcessHandler(max_workers=max_workers)
    for path in script_paths:
        handler.add_script(path)
    handler.run_all()
