import logging
import os
import sys

def setup_logger(name="NetworkTrafficAnalyzer"):
    """
    Sets up a logger that logs to both console and a file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Prevent adding handlers multiple times
    if logger.hasHandlers():
        return logger

    # Console Handler
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.INFO)
    c_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    c_handler.setFormatter(c_format)
    logger.addHandler(c_handler)

    # File Handler
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    f_handler = logging.FileHandler(os.path.join(log_dir, "app.log"))
    f_handler.setLevel(logging.DEBUG)
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_handler.setFormatter(f_format)
    logger.addHandler(f_handler)

    return logger

# Default logger instance
logger = setup_logger()
