import logging
import os
from logging import debug, error, info, warning  # noqa: F401


level = os.getenv('IDA_FEEDS_LOG_LEVEL', 'INFO').upper()
level = logging.getLevelName(level)

logging.basicConfig(
    format=r'{asctime} - {levelname} - {message}',
    style=r'{',
    datefmt=r'%Y-%m-%d %H:%M',
    level=level,
)
