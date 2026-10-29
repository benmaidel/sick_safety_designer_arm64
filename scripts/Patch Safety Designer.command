#!/bin/zsh
set -u
cd -- "${0:A:h}"
if ! command -v python3 >/dev/null 2>&1; then
  print 'Python 3 is required. See README.md in this folder.'
  read -r '?Press Return to close.'
  exit 1
fi
python3 patch_safety_designer.py "$@"
patch_result=$?
print ''
read -r '?Press Return to close.'
exit $patch_result
