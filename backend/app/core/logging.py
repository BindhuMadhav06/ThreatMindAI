import logging
import sys
from app.core.config import settings

def setup_logging():
    logging_level = logging.DEBUG if settings.DEBUG else logging.INFO
    
    logger = logging.getLogger("threatmind")
    logger.setLevel(logging_level)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging_level)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger

logger = setup_logging()
