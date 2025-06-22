import logging
import logging.handlers
import os
import sys
import threading
import warnings



def _get_base_path() -> str:
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        exe = os.path.abspath(sys.argv[0])
        return os.path.dirname(exe)

    utilities_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(utilities_dir)



def _get_log_file_path(filename: str = 'basilisk.log') -> str:
    return os.path.join(_get_base_path(), filename)



def setup_logger(
    name: str | None = None,
    log_file: str | None = None,
    level: int | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5
) -> logging.Logger:
    level = level or logging.DEBUG
    level_name = os.environ.get('BASILISK_LOG_LEVEL')
    if level_name:
        level = getattr(logging, level_name.upper(), level)
    handlers = []
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level) # type: ignore
    handlers.append(ch)
    if log_file is None:
        log_file = _get_log_file_path()
    fh = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    fh.setLevel(level) # type: ignore
    handlers.append(fh)
    fmt = (
        '%(asctime)s [%(levelname)s] %(name)s '
        '%(module)s.%(funcName)s:%(lineno)d [pid:%(process)d tid:%(thread)d '
        'threadName:%(threadName)s]: %(message)s'
    )
    datefmt = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(fmt, datefmt)
    for h in handlers:
        h.setFormatter(formatter)
    root = logging.getLogger(name) if name else logging.getLogger()
    root.setLevel(level) # type: ignore
    if not root.handlers:
        for h in handlers:
            root.addHandler(h)
    def _handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        root.error("Uncaught exception",
                   exc_info=(exc_type, exc_value, exc_traceback))
    sys.excepthook = _handle_exception
    if hasattr(threading, 'excepthook'):
        def _thread_excepthook(args):
            root.error(f"Uncaught threading exception in '{args.thread.name}'",
                       exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
        threading.excepthook = _thread_excepthook
    logging.captureWarnings(True)
    warnings.simplefilter('default')
    root.debug(
        f"Logger initialized (level={logging.getLevelName(level)}, " # type: ignore
        f"file={log_file}, maxBytes={max_bytes}, backups={backup_count})"
    )
    return root



logger = setup_logger()