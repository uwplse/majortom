default: filewriter directorymaker

filewriter: filewriter.c
	gcc -Wall -pthread filewriter.c -o filewriter

directorymaker: directorymaker.c
	gcc -Wall -pthread directorymaker.c -o directorymaker
clean:
	rm filewriter directorymaker

.PHONY: clean default
