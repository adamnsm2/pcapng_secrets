#define _GNU_SOURCE

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>


#define SECTION_HEADER_BLOCK_TYPE 0x0A0D0D0A
#define SIMPLE_PACKET_BLOCK_TYPE 0x00000003
#define ENHANCED_PACKET_BLOCK_TYPE 0x00000006
#define SECRET_BLOCK_TYPE 0x00000009

#define SECRET_BLOCK_SIZE 0x00000060

#define BYTE_ORDER_MAGIC 0x4D3C2B1A

#define RSA_LABEL 0x00000000
#define CLIENT_RANDOM_LABEL 0x00000001
#define ERROR_LABEL -1

#define CLIENT_RANDOM_BYTES 32
#define CLIENT_RANDOM_CHARS 2 * CLIENT_RANDOM_BYTES
#define SECRET_BYTES 48
#define SECRET_CHARS 2 * SECRET_BYTES

struct char_pair {
	char c1;
	char c2;
};

typedef struct secret_info {
	guint32 label;
	char cli_rand[CLIENT_RANDOM_BYTES];
	char secret[SECRET_BYTES];
 } secret_info;

 struct write_info {
 	FILE *file;
 	bool big_endian;
 };

guint32 convert_label_to_code(char *label) 
{
	if (strcmp(label, "RSA") == 0) return RSA_LABEL;
 	if (strcmp(label, "CLIENT_RANDOM") == 0) return CLIENT_RANDOM_LABEL;
 	return ERROR_LABEL;
}

char *code_to_label(guint32 code) {
	switch(code) {
		case(RSA_LABEL):
			return "RSA";
		case(CLIENT_RANDOM_LABEL):
			return "CLIENT_RANDOM";
		default:
			return "ERROR";
	}
}

char *set_hex_endianness(char *hex, int len, bool big_endian) {
	int x = 1;
	char *y = (char *)&x;
	bool sys_end = (*y+48 == '0');
	if (sys_end == big_endian) return hex;
	char *swap = malloc(sizeof(char) * len);
	int i;
	for (i = 0; i < len; i++) {
		swap[i] = hex[len - i - 1];
	}
	return swap;
}

char convert_hex_char(char in) {
	char hex = tolower(in);
	switch(hex) {
		case('0'):
			return 0;
		case('1'):
			return 1;
		case('2'):
			return 2;
		case('3'):
			return 3;
		case('4'):
			return 4;
		case('5'):
			return 5;
		case('6'):
			return 6;
		case('7'):
			return 7;
		case('8'):
			return 8;
		case('9'):
			return 9;
		case('a'):
			return 10;
		case('b'):
			return 11;
		case('c'):
			return 12;
		case('d'):
			return 13;
		case('e'):
			return 14;
		case('f'):
			return 15;
		default:
			printf("ERROR, DIDNT RECOGNIZE DIGIT!!!\n");
			return -1;
	}
} 

char convert_hex_byte(char *hex)
{
	char c1 = convert_hex_char(hex[0]);
	char c2 = convert_hex_char(hex[1]);
	char ret = (c1 << 4) + c2;
	return ret;
}

char *convert_hex_to_binary(char *hex, int num_chars)
{
	char *bin = malloc(sizeof(char) * num_chars / 2);
	for (int i = 0; i < num_chars / 2; i++) {
		bin[i] = convert_hex_byte(hex + (2 * i));
	}
	return bin;

}

char convert_digit_to_hex(char b) {
	switch(b) {
		case(0):
			return '0';
		case(1):
			return '1';
		case(2):
			return '2';
		case(3):
			return '3';
		case(4):
			return '4';
		case(5):
			return '5';
		case(6):
			return '6';
		case(7):
			return '7';
		case(8):
			return '8';
		case(9):
			return '9';
		case(10):
			return 'a';
		case(11):
			return 'b';
		case(12):
			return 'c';
		case(13):
			return 'd';
		case(14):
			return 'e';
		case(15):
			return 'f';
		default:
			printf("UNKNOWN DIGIT!!!\n");
			return -1;
	}

}

struct char_pair *convert_char_to_hex(char b) {

	char mask = 0xFF >> 4;

	struct char_pair *pair = malloc(sizeof(struct char_pair));
	pair->c1 = convert_digit_to_hex((b>>4)&mask);
	pair->c2 = convert_digit_to_hex(b & mask);
}

char *convert_bin_to_hex(char *bin, int num_bytes, bool upper) {
	char *hex = malloc(sizeof(char) * num_bytes * 2);
	for (int i = 0; i < num_bytes; i ++) {
		struct char_pair *pair = convert_char_to_hex(bin[i]);
		hex[i * 2] = (upper) ? toupper(pair->c1) : pair->c1;
		hex[i * 2 + 1] = (upper) ? toupper(pair->c2) : pair->c2;
		free(pair);
	}
	return hex;

}
