CC = gcc 
LIBS = -l pthread -lpcap
objects = dns_qps.o

dnsqps: $(objects)
	$(CC) -o dnsqps $(objects) $(LIBS) 

$(objects): %.o : %.c
	$(CC) -c $< -o $@

.PHONY: clean

clean:
	rm -f *.o dnsqps
