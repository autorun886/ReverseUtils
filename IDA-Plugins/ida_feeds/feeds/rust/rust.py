import glob
import hashlib
import mmap
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import traceback
from dataclasses import dataclass
from typing import Optional, Tuple

import requests

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from feeds.core.idahelper import Target

from . import logger, sigmake, util


class RustDownloadError(RuntimeError):
    pass


class RustMissingUrlException(RustDownloadError):
    pass


class RustMissingArchiveHashException(RustDownloadError):
    pass


class RustcHashGuessingException(Exception):
    pass


_RUSTC_RE = re.compile(
    rb'/rustc/(?P<hash>[0-9a-fA-F]{40})[/\\]?'
    rb'|rustc version (?P<version>[a-zA-Z0-9._-]+)'
)


def guess_rustc_hash_or_version(filepath: pathlib.Path) -> Optional[Tuple[str, str]]:
    with open(filepath, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for match in _RUSTC_RE.finditer(mm):
                if match.group('hash') is not None:
                    return 'hash', match.group('hash').decode('ascii')
                if match.group('version') is not None:
                    return 'version', match.group('version').decode('ascii')
    return None


@dataclass
class RustManifest:
    manifest: dict
    release: str

    @classmethod
    def loads(cls, version: str, data: str) -> 'RustManifest':
        return cls(tomllib.loads(data), version)

    @property
    def rustc_hash(self) -> Optional[str]:
        return self.manifest.get('pkg', {}).get('rustc', {}).get('git_commit_hash')

    def pkg_url(self, pkg: str, target: Target) -> str:
        target_base = (
            self.manifest.get('pkg', {}).get(pkg, {}).get('target', {}).get(target.value, {})
        )
        url = target_base.get('xz_url')
        if url:
            return url
        url = target_base.get('url')
        if url:
            return url
        raise RustMissingUrlException(f'No url for {pkg} {target}')

    def pkg_hash(self, pkg: str, target: Target) -> str:
        target_base = (
            self.manifest.get('pkg', {}).get(pkg, {}).get('target', {}).get(target.value, {})
        )
        hsh = target_base.get('xz_hash')
        if hsh:
            return hsh
        hsh = target_base.get('hash')
        if hsh:
            return hsh
        raise RustMissingArchiveHashException(f'No hash for {pkg} {target}')

    def rust_std_archive_url(self, target: Target) -> str:
        return self.pkg_url('rust-std', target)

    def rust_std_archive_hash(self, target: Target) -> str:
        return self.pkg_hash('rust-std', target)


def retrieve_rust_manifest(version: str) -> RustManifest:
    # aws --no-sign-request s3 ls s3://static-rust-lang-org/dist/channel-rust-1.77.2.toml
    # TODO: handle non-release versions
    url = f'https://static.rust-lang.org/dist/channel-rust-{version}.toml'
    try:
        resp = requests.get(url)
        manifest = RustManifest.loads(version, resp.text)
    except Exception:
        logger.error(traceback.format_exc())
        raise RustDownloadError(f'Failed to download {url}')
    return manifest


class RustArchiveHashMismatchException(Exception):
    pass


class RustCommitHashMismatchException(Exception):
    pass


class RustMultipleTagsException(Exception):
    pass


def get_rust_manifest(info: {}) -> RustManifest:
    # Guess rustc version from the given commit hash
    version = info['version']
    if version is None or version == '':
        raise RustArchiveHashMismatchException(
            f'Empty version for {info["target"]}: {info["hash"]}'
        )

    # Get the manifest from the S3 bucket
    manifest = retrieve_rust_manifest(version)
    if info.get('hash') and info['hash'] != manifest.rustc_hash:
        raise RustCommitHashMismatchException(
            f'Hash mismatch for version {version}: given {info["hash"]}, expected {manifest.rustc_hash}'
        )

    return manifest


def sha256_hasher(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_signature(maker: sigmake.Sigmake, info: {}) -> pathlib.Path:
    # TODO: cache (commit_hash, triple) -> (archive)

    with tempfile.TemporaryDirectory(prefix='ida-rust-autosig-') as tmpdir_s:
        tmpdir = pathlib.Path(tmpdir_s)
        target = info['target']
        commit_hash = info['hash']

        logger.info(f'Resolving archive url for {commit_hash} {target}')
        manifest = get_rust_manifest(info)

        url = manifest.rust_std_archive_url(target)
        remote_hash = manifest.rust_std_archive_hash(target)

        logger.info(f'Downloading archive from {url}')
        archive_path = tmpdir / 'archive.tar.xz'
        with requests.get(url, stream=True, timeout=30) as resp:
            resp.raise_for_status()
            with open(archive_path, 'wb') as out:
                shutil.copyfileobj(resp.raw, out)

        logger.info('Checking archive hash')
        with open(archive_path, 'rb') as inp:
            archive_hash = sha256_hasher(inp.read())

        if remote_hash.lower() != archive_hash.lower():
            raise RustArchiveHashMismatchException(
                f'Hash mismatch for {target} ({remote_hash} !== {archive_hash})'
            )

        extracted = tmpdir / 'extracted'
        extracted.mkdir()
        logger.info(f'Extracting archive to {extracted}')
        with tarfile.open(archive_path, 'r') as archive:
            if hasattr(tarfile, 'data_filter'):
                archive.extractall(extracted, filter='data')
            else:
                logger.warn('Extracting may be unsafe; consider updating Python')
                archive.extractall(extracted)

        # NOTE: PoC plugin further expands `.rlib` (i.e. `.a) archives into `.o` files.
        # `pelf` and friends seem to support `.a` files out of the box,
        # so I don't think we need that extra step.

        # Find all the `.rlib` / `.o` / '.a' files
        objects = []
        objects += glob.glob(str(extracted / '**/*.rlib'), recursive=True)
        objects += glob.glob(str(extracted / '**/*.o'), recursive=True)
        objects += glob.glob(str(extracted / '**/*.a'), recursive=True)
        objects.sort()
        for obj in objects:
            logger.debug(f'Found object: {obj}')

        pat = util.sig_dir() / f'rust-autosig-{commit_hash}-{target.value}.pat'
        sig = util.sig_dir() / f'rust-autosig-{commit_hash}-{target.value}.sig'
        sig_name = manifest.release

        maker.make_pat(target, pat, [pathlib.Path(p) for p in objects])
        maker.make_sig(sig_name, sig, pat)

        return sig
