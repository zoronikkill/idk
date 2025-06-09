# IDA Feeds 

> Manage FLIRT signatures.

# Notes

Can be run as a standalone app (`python feeds_app`) using IDALIB or as an IDAPython plugin.

# Install

The packages should be installed in the interpreter that IDA is using

- `python3 -m pip install -r requirements.txt`

## Other dependencies

- `idalib`
- `idapro`

## Linux & OSX

`ln -s $(pwd) $HOME/.idapro/plugins/ida_feeds`

## Windows

`mklink /D "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_feeds" "%cd%"`
