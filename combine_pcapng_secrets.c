#include "pcapng_secrets_common.h"


void skip_and_write_block(FILE *input, FILE *output)
{
 	char block_size[4];
 	size_t read = fread(block_size, 4, 1, input);
 	char block[*((guint32 *)block_size)];
 	fseek(input, -8, SEEK_CUR);
 	fread(block, *((guint32 *)block_size), 1, input);
 	fwrite(block, *((guint32 *)block_size), 1, output);
}



void write_secret(gpointer secret_ptr, gpointer args) {
	secret_info *info = (secret_info *)secret_ptr;
	struct write_info *write = (struct write_info *)args;
	
	guint32 block_type;
	guint32 total_block_size;
	char *cli_rand = set_hex_endianness(info->cli_rand, CLIENT_RANDOM_BYTES, write->big_endian);
	guint32 label;
	char *secret = set_hex_endianness(info->secret, SECRET_BYTES, write->big_endian);

	if (write->big_endian) {
		block_type = GUINT32_TO_BE(SECRET_BLOCK_TYPE);
		total_block_size = GUINT32_TO_BE((guint32)SECRET_BLOCK_SIZE);
		label = GUINT32_TO_BE(info->label);
	}
	else {
		block_type = GUINT32_TO_LE(SECRET_BLOCK_TYPE);
		total_block_size = GUINT32_TO_LE((guint32)SECRET_BLOCK_SIZE);
		label = GUINT32_TO_LE(info->label);
	}

	//printf("Secret out: %s\n", convert_bin_to_hex(secret, SECRET_BYTES, true));
	//printf("Secret bin: %u\n", *(int *)secret);

	fwrite(&block_type, 4, 1, write->file);
	fwrite(&total_block_size, 4, 1, write->file);
	fwrite(cli_rand, CLIENT_RANDOM_BYTES, 1, write->file);
	fwrite(&label, 4, 1, write->file);
	fwrite(secret, SECRET_BYTES, 1, write->file);
	fwrite(&total_block_size, 4, 1, write->file);
}

void combine_section(GSequence *secrets, FILE *input, FILE *output, bool big_endian);

void write_section_block(FILE *input, FILE *output, guint32 block_size, int num_secrets, bool big_endian) {
	// Seek to section size and read it
	fseek(input, 4, SEEK_CUR);
	char section_len[8];
	fread(section_len, 8, 1, input);

	long new_len;
	if (*(long *)section_len == -1) new_len = -1;
	else {

		char *section_len_e = set_hex_endianness(section_len, 8, big_endian);

		// Add the size of the new blocks we're adding
		long new_len = *(long *)section_len_e + (num_secrets * (long int)SECRET_BLOCK_SIZE);

		printf("Size of lu: %lu\n", sizeof(long));
		printf("Oldsize:\t%lu\nAdded:\t%lu\nNewsize:\t%lu\n",
			*(long *)section_len_e,(long)(num_secrets * SECRET_BLOCK_SIZE), new_len);
	}

	// Seek back to the beginning of the block so we can re-read (and write) the
	// part before the section size
	fseek(input, -24, SEEK_CUR);
	char first_half[16];
	fread(first_half, 16, 1, input);
	fwrite(first_half, 16, 1, output);

	// Write the new section size
	char *new_len_e = set_hex_endianness((char *)&new_len, 8, big_endian);
	fwrite((void *)new_len_e, 8, 1, output);

	// Seek past the section size, and read and write the rest of the block
	fseek(input, 8, SEEK_CUR);
	char second_half[block_size - 24];
	fread(second_half, block_size - 24, 1, input);
	fwrite(second_half, block_size - 24, 1, output);
}

void parse_section_header(GSequence *secrets, FILE *input_fd, FILE *output_fd) {
	char block_size[4];
	fread(block_size, 4, 1, input_fd);
	char byte_magic[4];
	fread(byte_magic, 4, 1, input_fd);
	bool big_endian = (*((guint32 *)byte_magic) == BYTE_ORDER_MAGIC);
	int num_secrets = g_sequence_get_length(secrets);
	write_section_block(input_fd, output_fd, *(guint32 *)block_size, num_secrets, big_endian);
	struct write_info *info = g_malloc(sizeof(struct write_info));
	info->big_endian = big_endian;
	info->file = output_fd;
	g_sequence_foreach(secrets, (GFunc)write_secret, (void *)info);
	combine_section(secrets, input_fd, output_fd, big_endian);
}

void combine_section(GSequence *secrets, FILE *input, FILE *output, bool big_endian)
{	
	// Will need to use GHashTable if using this table for real!!
	GSequence *seen = g_sequence_new(NULL);

	char block_type_char[4];
	guint32 block_type;
 	size_t read = fread(block_type_char, 4, 1, input);
 	while (read > 0) {
 		if (big_endian) block_type = GUINT32_TO_BE(*(guint32 *)block_type_char);
	 	else block_type = GUINT32_TO_LE(*(guint32 *)block_type_char);

	 	switch(block_type) {
	 		case(SECTION_HEADER_BLOCK_TYPE):
	 			parse_section_header(secrets, input, output);
	 			return;
	 		/*
	 		TO BE USED IF SECRET BLOCKS ARE INSERTED AT POINT OF HANDSHAKE
	 		case(SIMPLE_PACKET_BLOCK_TYPE):
	 			parse_simple_packet(secrets, seen, input, output, big_endian);
	 			break;
	 		case(ENHANCED_PACKET_BLOCK_TYPE):
	 			parse_enhanced_packet(secrets, seen, input, output, big_endian);
	 			break;
	 		*/
	 		default:
	 			skip_and_write_block(input, output);
	 	}
	 	read = fread(block_type_char, 4, 1, input);
 	}

}

GSequence *parse_secrets(const char *keylog) 
{
 	FILE *keysfd = fopen(keylog, "r");
 	if (keysfd == NULL) exit(EXIT_FAILURE);

 	// Will need to use GHashTable if using this table for real!!
 	GSequence *secrets = g_sequence_new(NULL);

 	char *line= NULL;
 	char *word = NULL;
 	size_t len = 0;
 	ssize_t success;

 	while((success = getline(&line, &len, keysfd)) != -1) {
 		if (len <= 0 || line[0] == '\n' || line[0] == '#') continue;
 		const char delim[3] = " \n";
 		word = strtok(line, delim);
 		if (word == NULL) continue;
 		secret_info *new_secret = g_malloc(sizeof(secret_info));
 		new_secret->label = convert_label_to_code(word);
 		if (new_secret->label == ERROR_LABEL) {
 			g_free(new_secret);
 			continue;
 		}
 		word = strtok(NULL, delim);
 		if (word == NULL || strlen(word) != CLIENT_RANDOM_CHARS) {
 			printf("continuing, cli_rand is %ld\n", strlen(word));
 			g_free(new_secret);
 			continue;
 		}

 		char *bin_word = convert_hex_to_binary(word, CLIENT_RANDOM_CHARS);
 		char *hex_word = convert_bin_to_hex(bin_word, CLIENT_RANDOM_BYTES, false);
 		memcpy(new_secret->cli_rand, bin_word, CLIENT_RANDOM_BYTES);
 		word = strtok(NULL, delim);
 		if (word == NULL || strlen(word) != SECRET_CHARS) {
 			printf("continuing, secret is %ld\n", strlen(word));
 			g_free(new_secret);
 			continue;
 		}
 		memcpy(new_secret->secret, convert_hex_to_binary(word, SECRET_CHARS), SECRET_BYTES);
 		g_sequence_append(secrets, (void *)new_secret);
 	}

 	fclose(keysfd);
 	return secrets;
}

void combine(const char *input_pcap, const char *keylog, const char *output_pcap) 
{
 	GSequence *secrets = parse_secrets(keylog);
 	FILE *input_fd = fopen(input_pcap, "r");
 	FILE *output_fd = fopen(output_pcap, "w");

 	char block_type[4];
 	size_t read = fread(block_type, 4, 1, input_fd);
	while (read > 0 && *((guint32 *)block_type) != SECTION_HEADER_BLOCK_TYPE) {
		skip_and_write_block(input_fd, output_fd);
		size_t read = fread(block_type, 4, 1, input_fd);
	}
	if(read > 0) parse_section_header(secrets, input_fd, output_fd);
	fclose(input_fd);
	fclose(output_fd);
}

int main(int argc, char *argv[])
{
	if (argc != 4) exit(EXIT_FAILURE);
	const char *input_pcap = argv[1];
	const char * keylog = argv[2];
	const char * output_pcap = argv[3];
	combine(input_pcap, keylog, output_pcap);
	return 1;
}




