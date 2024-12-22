////////////////////////////////////////////////////////////////////////
// COMP1521 24T2 --- Assignment 2: `rbuoy', a simple file synchroniser
// <https://cgi.cse.unsw.edu.au/~cs1521/24T2/assignments/ass2/index.html>
//
// Written by THARAN SINGH (z5428491) on 29/7/2024.
// Rbuoy is a program that can sync files across directories. 
// There is a sender and a receiver file with the same name
// And their contents are synced with this program
// It creates the receiver file if it doesn't exist
//
// 2023-07-12   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>


#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "rbuoy.h"

#define NUM_UPDATES_SIZE 3
#define SINGE_BYTE 1

// helpers
size_t get_file_size(const char *file_path);
void get_permissions(const char *file_path, char *permissions);
mode_t convert_permissions(char *permissions);
void apply_permissions(const char *file_path, char *permissions);
static uint64_t read_little_endian(FILE *file, int byte_size);
void write_little_endian(FILE *file, int byte_size, uint64_t value);


/// @brief Create a TABI file from an array of pathnames.
/// @param out_pathname A path to where the new TABI file should be created.
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.
void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames) {
    // TODO: implement this.

    // Hint: you will need to:
    //   * Open `out_pathname` using fopen, which will be the output TABI file.
    //   * For each pathname in `in_pathnames`:
    //      * Write the length of the pathname as a 2 byte little endian integer
    //      * Write the pathname
    //      * Check the size of the input file, e.g. using stat
    //      * Compute the number of blocks using number_of_blocks_in_file
    //      * Write the number of blocks as a 3 byte little endian integer
    //      * Open the input file, and read in blocks of size BLOCK_SIZE, and
    //         * For each block call hash_black to compute the hash
    //         * Write out that hash as an 8 byte little endian integer
    // Each time you need to write out a little endian integer you should
    // compute each byte using bitwise operations like <<, &, or |

    FILE *tabi = fopen(out_pathname, "w");
    if (tabi == NULL) {
        perror(out_pathname);
        exit(1);
    }
    unsigned int records = num_in_pathnames;

    // writing magic number
    fwrite(TYPE_A_MAGIC, sizeof(char), MAGIC_SIZE, tabi);

    fputc(records, tabi);
    
    for (int i = 0; i < records; i++) {
        FILE *current_file = fopen(in_pathnames[i], "rb");
        if (current_file == NULL) {
            perror(in_pathnames[i]);
            exit(1);
        }
        struct stat st;
        stat(in_pathnames[i], &st);

        uint16_t pathname_length = strlen(in_pathnames[i]);
        int n_blocks = number_of_blocks_in_file(st.st_size);

        write_little_endian(tabi, PATHNAME_LEN_SIZE, pathname_length);

        fwrite(in_pathnames[i], SINGE_BYTE, pathname_length, tabi);

        write_little_endian(tabi, NUM_BLOCKS_SIZE, n_blocks);

        if (n_blocks <= 0) {
            fclose(current_file);
            continue;
        }

        // loop over number of blocks and hash it
        uint64_t hashes[n_blocks];
        for (int j = 0; j < n_blocks; j++) {
            char block[BLOCK_SIZE];
            size_t bytes_read = fread(block, sizeof(char), BLOCK_SIZE, current_file);
            hashes[j] = hash_block(block, bytes_read);
            //printf("%016lx\n", hashes[j]);
        }

        // write the hashes
        for (int j = 0; j < n_blocks; j++) {
            uint64_t hash_bytes = hashes[j];
            fwrite(&hash_bytes, sizeof(uint64_t), 1, tabi);
        }


        fclose(current_file);

    }

    fclose(tabi);
}


/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.
void stage_2(char *out_pathname, char *in_pathname) {
    // TODO: implement this.
    FILE *tabi = fopen(in_pathname, "rb");
    if (tabi == NULL) {
        perror(in_pathname);
        exit(1);
    }

    FILE *tbbi = fopen(out_pathname, "w");
    if (tbbi == NULL) {
        perror(out_pathname);
        exit(1);
    }

    // write tbbi header
    unsigned char magic[MAGIC_SIZE];
    fread(magic, sizeof(char), MAGIC_SIZE, tabi);
    if ((magic[0] != TYPE_A_MAGIC[0]) | (magic[1] != TYPE_A_MAGIC[1]) | (magic[2] != TYPE_A_MAGIC[2]) | (magic[3] != TYPE_A_MAGIC[3])) {
        fprintf(stderr, "Failed to read tabi\n");
        exit(1);
    }

    int num_records;
    if ((num_records = fgetc(tabi)) == EOF) {
        fprintf(stderr, "Failed to number of records\n");
        exit(1);
    }
    fwrite(TYPE_B_MAGIC, sizeof(char), MAGIC_SIZE, tbbi);
    fputc(num_records, tbbi);
    
    for (int i = 0; i < num_records; i++) {
        size_t bytes_read;
        // read and write pathname length
        uint16_t pathname_length = read_little_endian(tabi, PATHNAME_LEN_SIZE);
        write_little_endian(tbbi, PATHNAME_LEN_SIZE, pathname_length);

        char pathname[pathname_length + 1];
        pathname[pathname_length] = '\0';
        bytes_read = fread(pathname, sizeof(char), pathname_length, tabi);
        if (bytes_read !=  pathname_length) {
            fprintf(stderr, "Failed to read pathname of record %d\n", i);
            exit(1);
        }
        fwrite(pathname, pathname_length, 1, tbbi);

        uint32_t num_blocks = read_little_endian(tabi, NUM_BLOCKS_SIZE);
        write_little_endian(tbbi, NUM_BLOCKS_SIZE, num_blocks);

        if (num_blocks == 0) {
            continue;
        }

        // read each hash
        // store into hashes array
        int hash_bytes_read;
        uint64_t hashes[num_blocks];
        for (int j = 0; j < num_blocks; j++) {
            hash_bytes_read = fread(&hashes[j], sizeof(char), 8, tabi);
            if (hash_bytes_read != 8) {
                fprintf(stderr, "Failed to hash %d in record %d\n", j, i);
                exit(1);
            }
        }

        size_t num_match_bytes = num_tbbi_match_bytes(num_blocks);

        FILE *receiver_file = fopen(pathname, "rb");
        
        // for every match
        int hash_count = 0;
        for (int j = 0; j < num_match_bytes; j++) {
            if (hash_count == num_blocks) {
                break;
            }
            uint8_t match_value = 0;
            int count = 0;
            // loop over every 8 blocks
            // to construct match byte
            while ((hash_count < num_blocks) && (count < 8)) {
                if (receiver_file == NULL) {
                    break;
                }
                uint64_t hash = hashes[hash_count];
                char block[BLOCK_SIZE];
                // get the hash of the block of the receivers file
                bytes_read = fread(block, sizeof(char), BLOCK_SIZE, receiver_file);
                uint64_t receiver_hash = hash_block(block, bytes_read);
                // compare and set the bit
                if (receiver_hash == hash) {
                    match_value |= (1 << (HASH_SIZE - count - 1));
                }
                count++;
                hash_count++;
            }
            fputc(match_value, tbbi);
        }

        if (receiver_file != NULL) {
            fclose(receiver_file);   
        }

    }
    if (fgetc(tabi) != EOF) {
        fprintf(stderr, "Data does not match num records %d\n", num_records);
        exit(1);
    }

    fclose(tabi);
    fclose(tbbi);

}


/// @brief Create a TCBI file from a TBBI file.
/// @param out_pathname A path to where the new TCBI file should be created.
/// @param in_pathname A path to where the existing TBBI file is located.
void stage_3(char *out_pathname, char *in_pathname) {
    // TODO: implement this.
    FILE *tbbi = fopen(in_pathname, "rb");
    if (tbbi ==  NULL) {
        perror(in_pathname);
        exit(1);
    }

    FILE *tcbi = fopen(out_pathname, "w");
    if (tcbi == NULL) {
        perror(out_pathname);
        exit(1);
    }

    unsigned char magic[MAGIC_SIZE];
    fread(magic, sizeof(char), MAGIC_SIZE, tbbi);
    if ((magic[0] != TYPE_B_MAGIC[0]) | (magic[1] != TYPE_B_MAGIC[1]) | (magic[2] != TYPE_B_MAGIC[2]) | (magic[3] != TYPE_B_MAGIC[3])) {
        fprintf(stderr, "Failed to read tbbi\n");
        exit(1);
    }

    int num_records;
    if ((num_records = fgetc(tbbi)) == EOF) {
        fprintf(stderr, "Failed to number of records\n");
        exit(1);
    }

    // write tbbi header
    fwrite(TYPE_C_MAGIC, sizeof(char), MAGIC_SIZE, tcbi);
    fputc(num_records, tcbi);

    for (int i = 0; i < num_records; i++) {
        char buffer[BLOCK_SIZE];

        // read and write pathname length
        uint16_t pathname_length = read_little_endian(tbbi, PATHNAME_LEN_SIZE);
        write_little_endian(tcbi, PATHNAME_LEN_SIZE, pathname_length);

        // read and write the pathname
        char pathname[pathname_length + 1];
        pathname[pathname_length] = '\0';
        int bytes_read = fread(pathname, sizeof(char), pathname_length, tbbi);
        if (bytes_read !=  pathname_length) {
            fprintf(stderr, "Failed to read pathname of record %d\n", i);
            exit(1);
        }
        fwrite(pathname, pathname_length, 1, tcbi);

        char permissions[MODE_SIZE + 1];
        permissions[MODE_SIZE] = '\0';

        get_permissions(pathname, permissions);

        fwrite(permissions, sizeof(char), MODE_SIZE, tcbi);

        uint32_t file_size = get_file_size(pathname);
        uint8_t mask = 0xFF;
        write_little_endian(tcbi, FILE_SIZE_SIZE, file_size);

        uint32_t num_blocks = read_little_endian(tbbi, NUM_BLOCKS_SIZE);
        size_t num_blocks_check = number_of_blocks_in_file(file_size);
        if (num_blocks != num_blocks_check) {
            fprintf(stderr, "Number of blocks mentioned in tabi is not equal to number of blocks for record %d\n", i);
            exit(1);
        }
        int num_matches = num_tbbi_match_bytes(num_blocks);

        // saving the indices of blocks that differ
        int block_index = 0;
        int* block_indices = malloc(num_blocks * sizeof(int));
        int saved_index_count = 0;
        uint32_t num_updates = 0;
        for (int j = 0; j < num_matches; j++) {
            uint8_t match_byte;
            int byte;
            if ((byte = fgetc(tbbi)) == EOF) {
                fprintf(stderr, "Failed to read match %d: unexpected EOF\n", j);
                exit(1);
            }
            match_byte = byte;
            if (j == num_matches - 1) {
                int blocks_remaining = (MATCH_BYTE_BITS * num_matches) - (num_blocks);
                mask = (1 << blocks_remaining) - 1;
                if ((match_byte & mask) != 0) {
                    fprintf(stderr, "Error in match bit padding\n");
                    exit(1);
                }
            }
            for (int k = 0; k < 8 && block_index < num_blocks; k++) {
                if (!((match_byte >> (7 - k)) & 1)) {
                    num_updates++;
                    block_indices[saved_index_count] = block_index;
                    saved_index_count++;
                }
                block_index++;
            }
        }

        write_little_endian(tcbi, NUM_UPDATES_SIZE, num_updates);
       
        FILE *sender_file = fopen(pathname, "rb");
        if (sender_file == NULL) {
            fprintf(stderr, "File from record %d does not exist\n", i);
            exit(1);
        }

        for (int j = 0; j < num_updates; j++) {
            write_little_endian(tcbi, BLOCK_INDEX_SIZE, block_indices[j]);
            // helper function to get block size
            if (fseek(sender_file, block_indices[j] * 256, SEEK_SET) != 0) {
                fprintf(stderr, "File from record %d does not have block %d\n", i, block_indices[j]);
                exit(1);
            }

            bytes_read = fread(buffer, sizeof(char), BLOCK_SIZE, sender_file);
            if (bytes_read < 0) {
                fprintf(stderr, "Failed to read block %d from record %d\n", block_indices[j], i);
                exit(1);
            }
            write_little_endian(tcbi, UPDATE_LEN_SIZE, bytes_read);
            fwrite(buffer, sizeof(char), bytes_read, tcbi);
        }

        fclose(sender_file);
        free(block_indices);
    }

    if (fgetc(tbbi) != EOF) {
        fprintf(stderr, "Data does not match num records %d\n", num_records);
        exit(1);
    }

    fclose(tbbi);
    fclose(tcbi);

}


/// @brief Apply a TCBI file to the filesystem.
/// @param in_pathname A path to where the existing TCBI file is located.
void stage_4(char *in_pathname) {
    // TODO: implement this.
    FILE *tcbi = fopen(in_pathname, "rb");
    if (tcbi == NULL) {
        perror(in_pathname);
        exit(1);
    }

    // set the header for TCBI file
    unsigned char magic[MAGIC_SIZE];
    fread(magic, sizeof(char), MAGIC_SIZE, tcbi);
    if ((magic[0] != TYPE_C_MAGIC[0]) | (magic[1] != TYPE_C_MAGIC[1]) | (magic[2] != TYPE_C_MAGIC[2]) | (magic[3] != TYPE_C_MAGIC[3])) {
        fprintf(stderr, "Failed to read tcbi\n");
        exit(1);
    }
    int num_records;
    if ((num_records = fgetc(tcbi)) == EOF) {
        fprintf(stderr, "Failed to number of records\n");
        exit(1);
    }

    for (int i = 0; i < num_records; i++) {
        // read TBBI record pathname length and pathname
        // write both to TCBI
        char buffer[BLOCK_SIZE];
        uint16_t pathname_length = read_little_endian(tcbi, PATHNAME_LEN_SIZE);

        char pathname[pathname_length + 1];
        pathname[pathname_length] = '\0';
        int bytes_read = fread(pathname, sizeof(char), pathname_length, tcbi);
        if (bytes_read !=  pathname_length) {
            fprintf(stderr, "Failed to read pathname of record %d\n", i);
            exit(1);
        }

        // read permission
        char sender_permissions[MODE_SIZE];
        fread(sender_permissions, 1, MODE_SIZE, tcbi);

        // open file from pathname
        // create if does not exist
        FILE *receiver_file = fopen(pathname, "rb+");
        if (receiver_file == NULL) {
            receiver_file = fopen(pathname, "w");
            if (receiver_file == NULL) {
                fprintf(stderr, "cannot create file %s\n", pathname);
                exit(EXIT_FAILURE);
            }
        }
        // modify permissions to match sender
        apply_permissions(pathname, sender_permissions);

        uint32_t sender_file_size = read_little_endian(tcbi, FILE_SIZE_SIZE);

        uint32_t num_updates = read_little_endian(tcbi, NUM_UPDATES_SIZE);

        // do nothing except match file size if no updates
        if (num_updates == 0) {
            truncate(pathname, sender_file_size);
            continue;
        }

        // for each update, calculate the block index
        // write at that block position
        for (int j = 0; j < num_updates; j++) {
            uint32_t block_index = read_little_endian(tcbi, 3);
            int position = block_index * BLOCK_SIZE;
            uint16_t update_length = read_little_endian(tcbi, UPDATE_LEN_SIZE);
            
            if (fseek(receiver_file, position, SEEK_SET) != 0) {
                fprintf(stderr, "Failed to seek position %d in file %s", position, pathname);
                exit(EXIT_FAILURE);
            }

            fread(buffer, 1, update_length, tcbi);
            fwrite(buffer, 1, update_length, receiver_file);

            // remove extra data at the last block of receiver
            if (update_length < BLOCK_SIZE) {
                int current_position = ftell(receiver_file);
                truncate(pathname, current_position);
            }
        }

        fclose(receiver_file);

    }
    if (fgetc(tcbi) != EOF) {
        fprintf(stderr, "Data does not match num records %d\n", num_records);
        exit(1);
    }

    fclose(tcbi);
}

/// @brief  Helper to get the size of a file
///
/// @param file_path  Path of file who's size to get    
///
/// @return size of the file
size_t get_file_size(const char *file_path) {
    struct stat st;
    if (stat(file_path, &st) < 0) {
        fprintf(stderr, "Failed to get file status\n");
        exit(1);
    }
    return st.st_size;
}

/// @brief  Helper for to get the permissions of a file
///         and construct a character array of permission bits
///
/// @param file_path  Path of file who's permissions to get
/// @param permissions  Character array of permission characters        
///
/// @return None
void get_permissions(const char *file_path, char *permissions) {
    struct stat st;
    if (stat(file_path, &st) < 0) {
        fprintf(stderr, "Failed to get file status\n");
        exit(1);
    }
    
    permissions[0] = '-';

    // owner permissions
    permissions[1] = (st.st_mode & S_IRUSR) ? 'r' : '-';
    permissions[2] = (st.st_mode & S_IWUSR) ? 'w' : '-';
    permissions[3] = (st.st_mode & S_IXUSR) ? 'x' : '-';

    // group permissions
    permissions[4] = (st.st_mode & S_IRGRP) ? 'r' : '-';
    permissions[5] = (st.st_mode & S_IWGRP) ? 'w' : '-';
    permissions[6] = (st.st_mode & S_IXGRP) ? 'x' : '-';

    // others permissions
    permissions[7] = (st.st_mode & S_IROTH) ? 'r' : '-';
    permissions[8] = (st.st_mode & S_IWOTH) ? 'w' : '-';
    permissions[9] = (st.st_mode & S_IXOTH) ? 'x' : '-';
}

/// @brief  Helper for apply_permissions() to create the mod
///         with bitwise operations
///
/// @param permissions  Character array of permission characters        
///
/// @return The mode with file permission bits
mode_t convert_permissions(char *permissions) {
    mode_t mode = 0;

    // Owner permissions
    if (permissions[1] == 'r') mode |= S_IRUSR; // Read
    if (permissions[2] == 'w') mode |= S_IWUSR; // Write
    if (permissions[3] == 'x') mode |= S_IXUSR; // Execute

    // Group permissions
    if (permissions[4] == 'r') mode |= S_IRGRP; // Read
    if (permissions[5] == 'w') mode |= S_IWGRP; // Write
    if (permissions[6] == 'x') mode |= S_IXGRP; // Execute

    // Others permissions
    if (permissions[7] == 'r') mode |= S_IROTH; // Read
    if (permissions[8] == 'w') mode |= S_IWOTH; // Write
    if (permissions[9] == 'x') mode |= S_IXOTH; // Execute

    return mode;
}

/// @brief Input an array of permission characters and the file path 
///         to set the permissions of a file
///
/// @param file_path    Path of the file to chmod
/// @param permissions  Character array of permission characters        
///
/// @return None.
void apply_permissions(const char *file_path, char *permissions) {
    // Convert the permissions array to mode_t
    mode_t mode = convert_permissions(permissions);

    // Apply permissions using chmod
    if (chmod(file_path, mode) == -1) {
        perror("Failed to change file permissions");
        exit(EXIT_FAILURE);
    }
}

/// @brief Read a stream of bytes stored in little endian and return them as big endian.
///
/// @param file      File descriptor of the file to read from
/// @param byte_size The number of bytes to read
///
/// @return The big endian version of the byte(s) read
uint64_t read_little_endian(FILE *file, int byte_size) {
    uint64_t value = 0;
    for (int i = 0; i < byte_size; i++) {
        uint64_t temp = 0;
        if ((temp = fgetc(file)) == EOF) {
            fprintf(stderr, "Failed to read bytes\n");
            exit(EXIT_FAILURE);
        }
        value = value | (temp << (i * 8));
    }
    return value;
}

/// @brief Write a value as a stream of little endian bytes
///
/// @param file      File descriptor of the file to write
/// @param byte_size The number of bytes to write
/// @param value     The value to write
///
/// @return None
void write_little_endian(FILE *file, int byte_size, uint64_t value) {
    for (int i = 0; i < byte_size; i++) {
        uint8_t temp = 0xff;
        temp = temp & (value >> (i * 8));
        fputc(temp, file);
    }
}
