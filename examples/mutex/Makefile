default: pinger ponger cond

pinger: pinger.c libproteinpills.a proteinpills.h
	gcc -Wall pinger.c libproteinpills.a -o pinger -ldl -pthread

ponger: ponger.c libproteinpills.a proteinpills.h
	gcc -Wall ponger.c libproteinpills.a -o ponger -ldl -pthread

cond: cond.c libproteinpills.a proteinpills.h
	gcc -Wall cond.c libproteinpills.a -o cond -ldl -pthread


libproteinpills.a:
	wget https://github.com/uwplse/proteinpills/releases/download/v1.0/libproteinpills.a

proteinpills.h:
	wget https://github.com/uwplse/proteinpills/releases/download/v1.0/proteinpills.h

clean:
	rm pinger ponger

.PHONY: clean default
