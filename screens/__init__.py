from importlib import import_module



__all__ = ["load"]



def load(name: str):
    return import_module(f"screens.{name}")
