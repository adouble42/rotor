CC=clang

rotor: libbz2 libntru progressbar.a libyescrypt.a libpasswdqc.a
	clang -o rotor rotor.c rotor-keys.c rotor-crypt.c salsa20.c rotor-console.c shake.c rotor-extra.c ../lib/libpasswdqc.a ../lib/libyescrypt.a ../lib/libbz2.a ../lib/libntru.a ../lib/progressbar.a -I../libntru/src -L/usr/local/lib -I../bzlib -I../include -I../progressbar/include -I./ -lcrypto -lm -ltermcap -lomp
libbz2:
	make -C ../bzlib libbz2.a
	mv ../bzlib/libbz2.a ../lib

libntru:
	gmake -C ../libntru static-lib
	mv ../libntru/libntru.a ../lib

libyescrypt.a:
	make -C ../zefcrypt all

libpasswdqc.a:
	make -C ../passwdqc-1.3.1 libpasswdqc.a

progressbar.a:
	make -C ../progressbar progressbar.a

clean:
	make -C ../bzlib clean
	gmake -C ../libntru clean
	make -C ../progressbar clean
	make -C ../zefcrypt clean
	rm rotor
