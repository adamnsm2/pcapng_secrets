CC=gcc
CFLAGS = `pkg-config --cflags --libs glib-2.0` -std=c99
DEPS = pcapng_secrets_common.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: combine_pcapng_secrets extract_secrets_pcapng

combine_pcapng_secrets: combine_pcapng_secrets.o
	gcc -o $@ $^ $(CFLAGS)

extract_secrets_pcapng: extract_secrets_pcapng.o
	gcc -o $@ $^ $(CFLAGS)



