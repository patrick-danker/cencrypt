# Cencrypt
This is a simple encryption CLI to protect your files from scans run by cloud providers. Note that this is NOT a security solution. please do not use it as such.

## Usage

## Keys
Keys will be stored in cleartext under `~/.config/cencrypt`. Nonces are stored in a sqlite database under the same directory.

## TODO
- decrypt files back to their original names - if files are not cleartext, they become unreadable
- create solution for nonce storage based on file name - probably in a sqlite db
- give option to use nonce or just a key
- name files based on uuid

