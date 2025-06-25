import os
import sys

def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for Nuitka exe"""
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path) 