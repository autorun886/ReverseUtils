import json
import os
import pathlib
from typing import Optional

from feeds import env
from feeds.core.idahelper import IDA

_cache_dir: Optional[pathlib.Path] = None


def cache_dir() -> pathlib.Path:
    global _cache_dir
    if not _cache_dir:
        cache_env = os.getenv('IDA_RUST_AUTOSIG_CACHE', None)
        if cache_env:
            cache = pathlib.Path(os.path.realpath(cache_env))
        else:
            cache = pathlib.Path(env.CACHE_DIR)
        cache.mkdir(exist_ok=True)
        _cache_dir = cache
    return _cache_dir


def package_dir() -> pathlib.Path:
    _package_dir = pathlib.Path(os.path.dirname(os.path.realpath(__file__))).parent.parent
    return _package_dir


def sig_dir() -> pathlib.Path:
    ret = cache_dir() / 'rust'
    ret.mkdir(exist_ok=True)
    return ret


def flair_dir():
    _flair_dir = IDA.get_ida_flair_dir()
    try:
        with open(package_dir() / 'config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        return _flair_dir
    else:
        _flair_conf = config.get('flair')
        if _flair_conf:
            _flair_dir = _flair_conf

    return pathlib.Path(_flair_dir)
