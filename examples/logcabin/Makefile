default: logcabin novdso.so

logcabin:
	cd logcabin-src; scons

novdso.so: novdso.c
	gcc -std=c99 -Wall -fPIC -shared -o novdso.so novdso.c

.PHONY: default logcabin
