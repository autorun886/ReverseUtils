# IDA Feeds 

> Manage FLIRT signatures and generate Rust signatures on demand.

# Notes

Can be run as a standalone app (`python feeds_app`) using IDALIB or as an IDAPython plugin.

# Install

IDA Feeds plugin is shipped with your IDA PRO instaler.

While the plugin can be used without setting up the dependencies, not all features will be available.

To install the dependencies run the following command.

- `python3 -m pip install -r requirements.txt`

## Other dependencies

- `git`
- `idalib`
- `idapro`
- `sigmake` / flair

## Linux & OSX

`ln -s $(pwd) $HOME/.idapro/plugins/ida_feeds`

## Windows

`mklink /D "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_feeds" "%cd%"`
