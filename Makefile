CC=clang

rotor: libbz2 libntru progressbar.a
	clang -o rotor rotor.c rotor-keys.c rotor-crypt.c rotor-console.c shake.c rotor-extra.c ../lib/libpasswdqc.a ../lib/libyescrypt.a ../lib/libbz2.a ../lib/libntru.a ../lib/progressbar.a -I../libntru/src -L/usr/local/lib -I../bzlib -I../include -I../progressbar/include -I./ -lcrypto -lm -ltermcap -lomp
libbz2:
	make -C ../bzlib libbz2.a
	mv ../bzlib/libbz2.a ../lib

libntru:
	gmake -C ../libntru static-lib
	mv ../libntru/libntru.a ../lib

progressbar.a:
	make -C ../progressbar progressbar.a

clean:
	make -C ../bzlib clean
	gmake -C ../libntru clean
	make -C ../progressbar clean
	rm rotor
