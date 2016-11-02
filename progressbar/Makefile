$(CC)=clang
$(AR)=ar

progressbar.a:
	make -C src progressbar.a
demo: progressbar.a
	$(CC) -o demo test/demo.c lib/progressbar.a -I./include -ltermcap
clean:
	make -C src clean
	rm demo
