CC=gcc 
CFLAGS=-c -I./
AR=ar
STATIC-C=skein.c skein_block.c SHA3api_ref.c
STATIC-O=skein.o skein_block.o SHA3api_ref.o
STATIC-NAME=libskein.a

all: $(STATIC-NAME)

skein_test: $(STATIC-NAME)
	$(CC) -o skein_test skein_test.c $(STATIC-NAME)

$(STATIC-NAME):
	$(CC) $(CFLAGS) $(STATIC-C)
	$(AR) cru $(STATIC-NAME) $(STATIC-O)
	cp $(STATIC-NAME) ../lib/$(STATIC-NAME)

clean:
	rm *.o *.a
