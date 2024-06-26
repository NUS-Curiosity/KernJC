"""
This module configures the logger for the project.
"""

import logging
import datetime
import re
from termcolor import colored

from src.util import ensure_dir
from src.global_vars import LOG_DIR


def uncolored(text):
    return re.sub(r'\x1b\[[0-9;]+m', '', text)


class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        color = None
        if record.levelname == colored('[*]', 'white'):
            color = 'white'
        elif record.levelname == colored('[+]', 'green'):
            color = 'green'
        elif record.levelname == colored('[!]', 'yellow'):
            color = 'yellow'
        elif record.levelname == colored('[-]', 'red'):
            color = 'red'
        elif record.levelname == colored('[!]', 'magenta'):
            color = 'magenta'
        
        if color:
            record.msg = colored(record.msg, color)
        
        return super().format(record)


class ConsoleFilter(logging.Filter):
    def filter(self, record):
        if record.levelno == logging.DEBUG:
            record.levelname = colored('[*]', 'white')
        elif record.levelno == logging.INFO:
            record.levelname = colored('[+]', 'green')
        elif record.levelno == logging.WARNING:
            record.levelname = colored('[!]', 'yellow')
        elif record.levelno == logging.ERROR:
            record.levelname = colored('[-]', 'red')
        elif record.levelno == logging.CRITICAL:
            record.levelname = colored('[!]', 'red')
        return True


class FileFilter(logging.Filter):
    def filter(self, record):
        if record.levelno == logging.DEBUG:
            record.levelname = 'DEBUG'
        elif record.levelno == logging.INFO:
            record.levelname = 'INFO'
        elif record.levelno == logging.WARNING:
            record.levelname = 'WARNING'
        elif record.levelno == logging.ERROR:
            record.levelname = 'ERROR'
        elif record.levelno == logging.CRITICAL:
            record.levelname = 'CRITICAL'
        record.msg = uncolored(record.msg)
        return True
    

def configure_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    # ch formatter: file_name:line_number: message
    formatter_ch = ConsoleFormatter(
        "%(levelname)s %(message)s"
    )
    ch.setFormatter(formatter_ch)
    ch_filter = ConsoleFilter()
    ch.addFilter(ch_filter)
    logger.addHandler(ch)

    ensure_dir(LOG_DIR)
    log_file = datetime.datetime.now().strftime("%Y-%m-%d") + ".log"
    fh = logging.FileHandler(LOG_DIR + "/" + log_file)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    fh_filter = FileFilter()
    fh.addFilter(fh_filter)
    logger.addHandler(fh)

    return logger
