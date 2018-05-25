#include "pcapng_secrets_common.h"

/**
 * Takes a pcapng file with SSL secrets embedded, and extracts the secrets to a separate file
 * Assumes all secrets are embedded in each section (in particular the first section)
 */




void parse_secret(FILE *input, FILE *output, bool big_endian) 
{
	fseek(input, 4, SEEK_CUR);

	char client_random[CLIENT_RANDOM_BYTES];
	fread(client_random, CLIENT_RANDOM_BYTES, 1, input);
	char *cli_rand_end = set_hex_endianness(client_random, CLIENT_RANDOM_BYTES, big_endian);

	char *cli_rand_e = convert_bin_to_hex(cli_rand_end,
		CLIENT_RANDOM_BYTES, false);

	char label_r[4];
	fread(label_r, 4, 1, input);
	glong label_int = (big_endian) ? GUINT32_TO_BE(*(guint32 *)label_r) : GUINT32_TO_LE(*(guint32 *)label_r);
	char *label = code_to_label(label_int);
	size_t label_len = strlen(label);

	char secret[SECRET_BYTES];
	fread(secret, SECRET_BYTES, 1, input);
	char *secret_e = convert_bin_to_hex(set_hex_endianness(secret, SECRET_BYTES, big_endian), SECRET_BYTES, true);

	fseek(input, 4, SEEK_CUR);
	
	char *line = malloc(sizeof(char) * (label_len + CLIENT_RANDOM_CHARS + SECRET_CHARS + 3));
	size_t idx = 0;
	memcpy(line, label, label_len);
	idx += label_len;
	line[idx++] = ' ';
	memcpy(line + idx, cli_rand_e, CLIENT_RANDOM_CHARS);
	idx += CLIENT_RANDOM_CHARS;
	line[idx++] = ' ';
	memcpy(line + idx, secret_e, SECRET_CHARS);
	idx += SECRET_CHARS;
	line[idx++] = '\n';
	fwrite(line, idx, 1, output);
}

void skip_block(FILE *input)
{
 	char block_size[4];
 	size_t read = fread(block_size, 4, 1, input);
 	char block[*((guint32 *)block_size)];
 	fseek(input, *((guint32 *)block_size)-8, SEEK_CUR);
}

void extract_section(FILE *input, FILE *output, bool big_endian)
{	
	char block_type_char[4];
	guint32 block_type;
 	size_t read = fread(block_type_char, 4, 1, input);
 	while (read > 0) {
 		if (big_endian) block_type = GUINT32_TO_BE(*(guint32 *)block_type_char);
	 	else block_type = GUINT32_TO_LE(*(guint32 *)block_type_char);

	 	switch(block_type) {
	 		case(SECTION_HEADER_BLOCK_TYPE):
	 			return;
	 		case(SECRET_BLOCK_TYPE):
	 			parse_secret(input, output, big_endian);
	 			break;
	 		default:
	 			skip_block(input);
	 	}
	 	read = fread(block_type_char, 4, 1, input);
 	}

}



void parse_section_header(FILE *input_fd, FILE *output_fd) {
	char block_type[4];
	fseek(input_fd, 4, SEEK_CUR);
	fread(block_type, 4, 1, input_fd);
	bool big_endian = (*((guint32 *)block_type) == BYTE_ORDER_MAGIC);
	fseek(input_fd, -8, SEEK_CUR);
	skip_block(input_fd);
	extract_section(input_fd, output_fd, big_endian);
}

void extract(const char *input_pcap, const char *output)
{
 	FILE *input_fd = fopen(input_pcap, "r");
 	FILE *output_fd = fopen(output, "w");

 	char block_type[4];
 	size_t read = fread(block_type, 4, 1, input_fd);
	while (read > 0 && *((guint32 *)block_type) != SECTION_HEADER_BLOCK_TYPE) {
		skip_block(input_fd);
		size_t read = fread(block_type, 4, 1, input_fd);
	}
	if(read > 0) parse_section_header(input_fd, output_fd);
	fclose(input_fd);
	fclose(output_fd);
}

int main(int argc, char *argv[])
{
	if (argc != 3) exit(EXIT_FAILURE);
	const char *input_pcap = argv[1];
	const char * keylog = argv[2];
	extract(input_pcap, keylog);

	int x = 1;
	char *y = (char *)&x;
	bool sys_end = (*y+48 == '0');

	return 1;
}
