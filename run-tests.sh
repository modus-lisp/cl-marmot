#!/bin/sh
# Run the cl-marmot test suite under SBCL.  Usage: ./run-tests.sh [name-substring]
cd "$(dirname "$0")"
exec sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval "(push (truename \".\") asdf:*central-registry*)" \
  --eval '(asdf:load-system :cl-marmot/test)' \
  --eval "(sb-ext:exit :code (if (cl-marmot/test:run-tests :only $( [ -n "$1" ] && echo "\"$1\"" || echo nil) :verbose t) 0 1))"
