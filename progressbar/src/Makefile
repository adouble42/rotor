$CC=clang
$AR=ar

progressbar.a:
	$(CC) -c *.c -I../include
	$(AR) cru ../../lib/progressbar.a *.o
clean:
	rm *.o ../lib/*.a
