CC=clang

rotor: libbz2 libntru progressbar.a
	clang -o rotor rotor.c rotor-keys.c rotor-crypt.c shake.c rotor-extra.c ../lib/libbz2.a ../lib/libntru.a ../lib/progressbar.a -I../libntru/src -I../bzlib -I../progressbar/include -I./ -lcrypto -lm -ltermcap
libbz2:
	make -C ../bzlib libbz2.a
	mv ../bzlib/libbz2.a ../lib

libntru:
	gmake -C ../libntru static-lib
	mv ../libntru/libntru.a ../lib

progressbar.a:
	make -C ../progressbar progressbar.a
	mv ../progressbar/lib/progressbar.a ../lib
clean:
	make -C ../bzlib clean
	gmake -C ../libntru clean
	make -C ../progressbar clean
	rm rotor
