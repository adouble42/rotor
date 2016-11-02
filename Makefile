all:
	make -C src rotor
clean:
	make -C src clean
	rm lib/*
