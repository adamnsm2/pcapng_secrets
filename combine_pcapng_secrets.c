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

void combine_section(FILE *secrets, FILE *input, FILE *output, bool big_endian);

long write_section_block(FILE *input, FILE *output, guint32 block_size, bool big_endian) {
	// Seek to section size and read it
	fseek(input, 4, SEEK_CUR);
	char section_len[8];
	fread(section_len, 8, 1, input);

	// Seek back to the beginning of the block so we can re-read (and write) the
	// part before the section size
	fseek(input, -24, SEEK_CUR);
	char first_half[16];
	fread(first_half, 16, 1, input);
	fwrite(first_half, 16, 1, output);

	// Write the new section size
	long size_offset;
	if (*(int64_t *)section_len == -1) size_offset = -1;
	else size_offset = ftell(output);
	fwrite((void *)section_len, 8, 1, output);

	// Seek past the section size, and read and write the rest of the block
	fseek(input, 8, SEEK_CUR);
	char second_half[block_size - 24];
	fread(second_half, block_size - 24, 1, input);
	fwrite(second_half, block_size - 24, 1, output);

	return size_offset;
}

void write_secrets(FILE *secrets, FILE *output, long total_size_offset, bool big_endian) {
	guint32 block_type;
	guint32 total_block_size;

	if (big_endian) {
		block_type = GUINT32_TO_BE(SECRET_BLOCK_TYPE);
	}
	else {
		block_type = GUINT32_TO_LE(SECRET_BLOCK_TYPE);
	}

	fwrite(&block_type, 4, 1, output);

	long block_size_offset = ftell(output);

	// Leave room for the block size and num lines, once calculated
	fseek(output, 8, SEEK_CUR);

	// Write the keylog file into the output, size BUF_SIZE at a time
	char buffer[BUF_SIZE];

	int32_t lines = 0;
	long start = ftell(output);

	for(;;) {
		char buf[512];
		if (!fgets(buf, 512, secrets)) {
			break;
		}
		lines++;
		fwrite(buffer, 512, 1, output);
	}

	long end = ftell(output);

	long total = MIN_SDB_SIZE + (end - start);

	// Pad to 32-bit alignment
	if (total % 4 != 0) {
		size_t pad = 4 - (total % 4);
		total += pad;
		char *zeroes = calloc(pad, sizeof(char));
		fwrite(zeroes, pad, 1, output);
	}


	// Note: cannot handle keylog files over 4 GiB
	if (big_endian) total_block_size = GUINT32_TO_BE((guint32)total);
	else total_block_size = GUINT32_TO_LE((guint32)total);

	/* Write the block size to the appropriate places */
	fwrite(&total_block_size, 4, 1, output);	// End of the block

	// Update total section size
	if (total_size_offset != -1) {
		fseek(output, total_size_offset, SEEK_SET);
		char section_len[8];
		fread(section_len, 8, 1, output);
		int64_t *sec_len_host = (int64_t *)set_hex_endianness(section_len, 8, big_endian);
		*sec_len_host += total;
		char *new_section_len = set_hex_endianness((char *)sec_len_host, 8, big_endian);
		fwrite(new_section_len, 8, 1, output);
	}

	// Beginning of block
	fseek(output, block_size_offset, SEEK_SET);
	fwrite(&total_block_size, 4, 1, output);
	fwrite(&lines, 4, 1, output);

	// Seek to end
	fseek(output, 0, SEEK_END);


}

void parse_section_header(FILE *secrets, FILE *input_fd, FILE *output_fd) {
	char block_size[4];
	fread(block_size, 4, 1, input_fd);
	char byte_magic[4];
	fread(byte_magic, 4, 1, input_fd);
	bool big_endian = (*((guint32 *)byte_magic) == BYTE_ORDER_MAGIC);
	long total_size_offset = write_section_block(input_fd, output_fd, *(guint32 *)block_size, big_endian);
	write_secrets(secrets, output_fd, total_size_offset, big_endian);
	combine_section(secrets, input_fd, output_fd, big_endian);
}

void combine_section(FILE *secrets, FILE *input, FILE *output, bool big_endian)
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

void combine(const char *input_pcap, const char *keylog, const char *output_pcap) 
{
 	FILE *secrets = fopen(keylog, "r");
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




