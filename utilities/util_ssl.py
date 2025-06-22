import ssl
import certifi
from .util_logger import logger



def create_ssl_context() -> ssl.SSLContext:
    try:
        cafile = certifi.where()
        return ssl.create_default_context(cafile=cafile)
    except Exception as e:
        logger.warning(
            f"Failed to load certifi CA bundle: {e}; falling back to system store"
        )
        return ssl.create_default_context()