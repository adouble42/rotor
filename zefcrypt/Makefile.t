BINDIR = bin
CFLAGS = -O3 -Wall -Wextra -pedantic -std=c99

BLAKE256 = blake256.c
BLAKE512 = blake512.c
BLAKESUM = blakesum.c
BLAKETESTS = tests.c

all: blake256sum   \
     blake224sum   \
     blake256hmac  \
     blake224hmac  \
     blake512sum   \
     blake384sum   \
     blake512hmac  \
     blake384hmac  \
     blake256tests \
     blake512tests

blake256sum: $(BINDIR)/blake256sum
$(BINDIR)/blake256sum: $(BLAKESUM) $(BLAKE256) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE256) $< -o $@ -DBLAKE256

blake224sum: $(BINDIR)/blake224sum
$(BINDIR)/blake224sum: $(BLAKESUM) $(BLAKE256) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE256) $< -o $@ -DBLAKE224

blake256hmac: $(BINDIR)/blake256hmac
$(BINDIR)/blake256hmac: $(BLAKESUM) $(BLAKE256) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE256) $< -o $@ -DBLAKE256 -DHMAC_MODE

blake224hmac: $(BINDIR)/blake224hmac
$(BINDIR)/blake224hmac: $(BLAKESUM) $(BLAKE256) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE256) $< -o $@ -DBLAKE224 -DHMAC_MODE

blake512sum: $(BINDIR)/blake512sum
$(BINDIR)/blake512sum: $(BLAKESUM) $(BLAKE512) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE512) $< -o $@ -DBLAKE512

blake384sum: $(BINDIR)/blake384sum
$(BINDIR)/blake384sum: $(BLAKESUM) $(BLAKE512) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE512) $< -o $@ -DBLAKE384

blake512hmac: $(BINDIR)/blake512hmac
$(BINDIR)/blake512hmac: $(BLAKESUM) $(BLAKE512) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE512) $< -o $@ -DBLAKE512 -DHMAC_MODE

blake384hmac: $(BINDIR)/blake384hmac
$(BINDIR)/blake384hmac: $(BLAKESUM) $(BLAKE512) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE512) $< -o $@ -DBLAKE384 -DHMAC_MODE

blake256tests: $(BINDIR)/blake256tests
$(BINDIR)/blake256tests: $(BLAKETESTS) $(BLAKE256) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE256) $< -o $@ -DBLAKE256

blake512tests: $(BINDIR)/blake512tests
$(BINDIR)/blake512tests: $(BLAKETESTS) $(BLAKE512) | $(BINDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BLAKE512) $< -o $@ -DBLAKE512

$(BINDIR):
	@mkdir -p $(BINDIR)

clean:
	rm -rf $(BINDIR)
