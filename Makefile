
name = aes-ctr-sparct4
type = sync
std = -std=gnu99 -Wa,-Av9e

srcdir = .
root := $(shell \
  cd "$(srcdir)"; root="$(srcdir)"; \
  while [ "`pwd`" != "/" ]; do \
    if [ -r "`pwd`/test/ecrypt-test.mk" ]; then  \
      echo $$root; exit; \
    fi; \
    cd ..; root="$$root"/..; \
  done; \
  echo ".")

include $(root)/test/ecrypt-test.mk

