#!/usr/bin/env bash
# Wraps site/page.html (title, styles and body content) into a standalone
# site/index.html that any static host can serve.
set -euo pipefail
cd "$(dirname "$0")/../site"
python3 - <<'PY'
src = open("page.html").read()
cut = src.index("</style>") + len("</style>")
head, body = src[:cut], src[cut:]
open("index.html", "w").write(
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    + head + "\n</head>\n<body>\n" + body.strip() + "\n</body>\n</html>\n")
PY
echo "wrote site/index.html"
