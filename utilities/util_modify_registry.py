import winreg
from typing import Any, Union, Optional
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup



VIEW_FLAG = winreg.KEY_WOW64_64KEY if hasattr(winreg, 'KEY_WOW64_64KEY') else 0
_HIVE_MAPPING = {
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKU': winreg.HKEY_USERS,
    'HKEY_USERS': winreg.HKEY_USERS,
    'HKCC': winreg.HKEY_CURRENT_CONFIG,
    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
}



def _resolve_hive(hive: Union[str, int]) -> int:
    if isinstance(hive, int):
        return hive
    key = hive.upper()
    if key in _HIVE_MAPPING:
        return _HIVE_MAPPING[key]
    raise ValueError(f"Unknown registry hive: {hive!r}")



def set_value(
    hive: Union[str, int],
    key_path: str,
    name: str,
    value: Any,
    value_type: Optional[int] = None
) -> None:
    try:
        hive_const = _resolve_hive(hive)
        if value_type is None:
            if isinstance(value, int):
                value_type = winreg.REG_DWORD
            elif isinstance(value, str):
                value_type = winreg.REG_SZ
            elif isinstance(value, bytes):
                value_type = winreg.REG_BINARY
            else:
                raise ValueError(f"Unsupported registry value type: {type(value)}")
        access = winreg.KEY_WRITE | VIEW_FLAG
        with winreg.CreateKeyEx(hive_const, key_path, 0, access) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)
        logger.info(f"Set registry value: {hive}\\{key_path}\\{name} = {value!r} (type={value_type})")
    except Exception as e:
        logger.exception(f"Error setting registry value {hive}\\{key_path}\\{name}: {e}")
        show_error_popup(
            f"Failed to set registry value:\n{hive}\\{key_path}\\{name}\n\n{e}",
            allow_continue=False
        )
        raise



def get_value(
    hive: Union[str, int],
    key_path: str,
    name: str
) -> Any:
    try:
        hive_const = _resolve_hive(hive)
        access = winreg.KEY_READ | VIEW_FLAG
        with winreg.OpenKey(hive_const, key_path, 0, access) as key:
            val, _ = winreg.QueryValueEx(key, name)
            logger.info(f"Read registry value: {hive}\\{key_path}\\{name} = {val!r}")
            return val
    except FileNotFoundError:
        logger.warning(f"Registry value not found: {hive}\\{key_path}\\{name}")
        return None
    except Exception as e:
        logger.exception(f"Error reading registry value {hive}\\{key_path}\\{name}: {e}")
        show_error_popup(
            f"Failed to read registry value:\n{hive}\\{key_path}\\{name}\n\n{e}",
            allow_continue=False
        )
        raise



def delete_value(
    hive: Union[str, int],
    key_path: str,
    name: str
) -> None:
    try:
        hive_const = _resolve_hive(hive)
        access = winreg.KEY_WRITE | VIEW_FLAG
        with winreg.OpenKey(hive_const, key_path, 0, access) as key:
            winreg.DeleteValue(key, name)
        logger.info(f"Deleted registry value: {hive}\\{key_path}\\{name}")
    except FileNotFoundError:
        logger.warning(f"Registry value to delete not found: {hive}\\{key_path}\\{name}")
    except Exception as e:
        logger.exception(f"Error deleting registry value {hive}\\{key_path}\\{name}: {e}")
        show_error_popup(
            f"Failed to delete registry value:\n{hive}\\{key_path}\\{name}\n\n{e}",
            allow_continue=False
        )
        raise



def create_key(
    hive: Union[str, int],
    key_path: str
) -> None:
    try:
        hive_const = _resolve_hive(hive)
        access = winreg.KEY_WRITE | VIEW_FLAG
        with winreg.CreateKeyEx(hive_const, key_path, 0, access):
            pass
        logger.info(f"Created registry key: {hive}\\{key_path}")
    except Exception as e:
        logger.exception(f"Error creating registry key {hive}\\{key_path}: {e}")
        show_error_popup(
            f"Failed to create registry key:\n{hive}\\{key_path}\n\n{e}",
            allow_continue=False
        )
        raise



def delete_key(
    hive: Union[str, int],
    key_path: str
) -> None:
    try:
        hive_const = _resolve_hive(hive)
        if hasattr(winreg, 'DeleteKeyEx'):
            winreg.DeleteKeyEx(hive_const, key_path, VIEW_FLAG, 0)
        else:
            parent_path, _, sub_key = key_path.rpartition('\\')
            with winreg.OpenKey(hive_const, parent_path, 0, winreg.KEY_WRITE | VIEW_FLAG) as parent:
                winreg.DeleteKey(parent, sub_key)
        logger.info(f"Deleted registry key: {hive}\\{key_path}")
    except FileNotFoundError:
        logger.warning(f"Registry key to delete not found: {hive}\\{key_path}")
    except Exception as e:
        logger.exception(f"Error deleting registry key {hive}\\{key_path}: {e}")
        show_error_popup(
            f"Failed to delete registry key:\n{hive}\\{key_path}\n\n{e}",
            allow_continue=False
        )
        raise