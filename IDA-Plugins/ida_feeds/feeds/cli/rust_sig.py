import pathlib
import sys

from feeds.ui.rust import process


def main(flair_path: str, binary_path: str):
    process(pathlib.Path(flair_path), pathlib.Path(binary_path))


if __name__ == '__main__':
    main(*sys.argv[1:])
