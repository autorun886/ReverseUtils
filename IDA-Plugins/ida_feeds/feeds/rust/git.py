import json
import pathlib
import shutil
import subprocess

from . import logger, util


def is_valid_repo(repo: pathlib.Path) -> bool:
    # We don't care about failures (we consider it False)
    ret = subprocess.run(
        ['git', '-C', str(repo / '.git'), 'rev-parse', '--is-inside-git-dir'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,  # Just to kill the output in case of error
    )
    return ret.stdout.strip() == b'true'


def fetch_rust_repo() -> pathlib.Path:
    repo_path = util.cache_dir() / 'rust-git'
    if not is_valid_repo(repo_path):
        subprocess.check_call(
            [
                'git',
                'clone',
                'https://github.com/rust-lang/rust.git',
                '--filter=blob:none',
                '--no-checkout',
                str(repo_path),
            ],
        )
        assert is_valid_repo(repo_path)

    return repo_path


commit_cache_path = util.cache_dir() / 'rust-git-tags.json'
_commit_to_tags = {}
if commit_cache_path.exists():
    try:
        with open(commit_cache_path, 'r') as inp:
            _commit_to_tags = json.load(inp)
    except json.JSONDecodeError:
        logger.error(f'Failed to load {commit_cache_path}')
    else:
        logger.debug(f'Loaded {commit_cache_path}')
else:
    commit_cache_path = util.package_dir() / 'rust-git-tags.json'
    if commit_cache_path.exists():
        try:
            with open(commit_cache_path, 'r') as inp:
                _commit_to_tags = json.load(inp)
        except json.JSONDecodeError:
            logger.error(f'Failed to load {commit_cache_path}')
        else:
            logger.debug(f'Loaded {commit_cache_path}')

if len(_commit_to_tags) == 0:
    logger.error(
        f'No tags found in {commit_cache_path}. Please run `python3 -m feeds.cli.rust_tags` to generate tags.'
    )


def commit_to_tag(commit_hash: str) -> str:
    return _commit_to_tags.get(commit_hash)


def remove_suffix(input_string, suffix):
    if suffix and input_string.endswith(suffix):
        return input_string[: -len(suffix)]
    return input_string


def remove_prefix(input_string, prefix):
    if prefix and input_string.startswith(prefix):
        return input_string[len(prefix) :]
    return input_string


def create_tags_json() -> pathlib.Path:
    try:
        repo = fetch_rust_repo()

        output = subprocess.check_output(
            ['git', '-C', str(repo), 'show-ref', '--tags', '-d'], text=True
        )
        commits_with_tags = {}

        for line in output.splitlines():
            commit_hash, tag = line.split(' ', 1)
            tag = remove_suffix(tag, '^{}')
            tag = remove_prefix(tag, 'refs/tags/')
            commits_with_tags[commit_hash] = tag

        with open(commit_cache_path, 'w') as outfile:
            json.dump(commits_with_tags, outfile)
            logger.info(f'Created {commit_cache_path}')

        logger.info(f'Removing git clone from {repo}')
        shutil.rmtree(repo)

        return commit_cache_path
    except subprocess.CalledProcessError as e:
        print(f'Error executing git command: {e}')
    except Exception as e:
        print(f'An error occurred: {e}')
