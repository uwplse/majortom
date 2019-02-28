default: pinger ponger

pinger: pinger.c
	gcc -Wall -pthread pinger.c -o pinger

ponger: ponger.c
	gcc -Wall -pthread ponger.c -o ponger

clean:
	rm pinger ponger

.PHONY: clean default
