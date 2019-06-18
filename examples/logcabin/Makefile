default: logcabin novdso.so bootstrap

bootstrap:
	rm -rf /tmp/storage1 /tmp/storage2 /tmp/storage3
	logcabin-src/build/LogCabin --config logcabin-1.conf --bootstrap

logcabin:
	cd logcabin-src; scons

novdso.so: novdso.c
	gcc -std=c99 -Wall -fPIC -shared -o novdso.so novdso.c

.PHONY: default logcabin bootstrap
