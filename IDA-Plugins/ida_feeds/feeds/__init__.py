import logging
import os

level = os.getenv('IDA_FEEDS_LOG_LEVEL', 'INFO').upper()
level = logging.getLevelName(level)

formatter = logging.Formatter(
    # fmt=r'%(asctime)s.%(msecs)03d %(levelname)-10s %(name)-20s %(message)s',
    fmt=r'%(levelname)-10s %(name)-20s %(message)s',
    style=r'%',
    datefmt=r'%Y-%m-%d %H:%M:%S',
)
ch = logging.StreamHandler()
ch.setLevel(level)
ch.setFormatter(formatter)
logger = logging.getLogger(f'{__name__}')
logger.setLevel(level)
logger.addHandler(ch)
