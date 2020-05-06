default: redis novdso.so

redis:
	cd redis-src; make

novdso.so: novdso.c
	gcc -std=c99 -Wall -fPIC -shared -o novdso.so novdso.c

.PHONY: default logcabin
