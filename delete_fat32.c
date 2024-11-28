#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_PASSES 3
#define MAX_PATH_COMPONENTS 256

typedef struct
{
    unsigned char ignored[3];
    unsigned char system_id[8];
    unsigned char sector_size[2];
    unsigned char sec_per_clus;
    unsigned short reserved;
    unsigned char fats;
    unsigned short root_entries;
    unsigned short total_sect_short;
    unsigned char media;
    unsigned short fat_length;
    unsigned short secs_track;
    unsigned short heads;
    unsigned int hidden;
    unsigned int total_sect;
    struct
    {
        unsigned int length;
        unsigned short flags;
        unsigned char version[2];
        unsigned int root_cluster;
        unsigned short info_sector;
        unsigned short backup_boot;
        unsigned short reserved2[6];
        unsigned char drive_number;
        unsigned char state;
        unsigned char signature;
        unsigned char vol_id[4];
        unsigned char vol_label[11];
        unsigned char fs_type[8];
    } fat32;
} __attribute__((packed)) FATBootSector;

typedef struct
{
    unsigned char name[11];
    unsigned char attr;
    unsigned char ntres;
    unsigned char crtTimeTenth;
    unsigned char crtTime[2];
    unsigned char crtDate[2];
    unsigned char lstAccDate[2];
    unsigned char fstClusHI[2];
    unsigned char wrtTime[2];
    unsigned char wrtDate[2];
    unsigned char fstClusLO[2];
    unsigned char file_size[4];
} __attribute__((packed)) DirEntry;

typedef struct
{
    unsigned char ord;
    unsigned char name1[10];
    unsigned char attr;
    unsigned char type;
    unsigned char chksum;
    unsigned char name2[12];
    unsigned short fstClusLO;
    unsigned char name3[4];
} __attribute__((packed)) LongDirEntry;

unsigned short read_le16(const unsigned char *bytes)
{
    return (unsigned short)(bytes[0] | (bytes[1] << 8));
}

unsigned int read_le32(const unsigned char *bytes)
{
    return (unsigned int)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
}

void utf16le_to_utf8(const unsigned char *utf16le_str, int utf16le_len, char *utf8_str, int utf8_len)
{
    int i = 0, j = 0;
    while (i + 1 < utf16le_len && j < utf8_len - 1)
    {
        unsigned short unicode_char = utf16le_str[i] | (utf16le_str[i + 1] << 8);
        if (unicode_char == 0xFFFF || unicode_char == 0x0000)
            break;
        if (unicode_char < 0x80)
        {
            utf8_str[j++] = unicode_char & 0x7F;
        }
        else if (unicode_char < 0x800)
        {
            utf8_str[j++] = 0xC0 | ((unicode_char >> 6) & 0x1F);
            utf8_str[j++] = 0x80 | (unicode_char & 0x3F);
        }
        else
        {
            utf8_str[j++] = 0xE0 | ((unicode_char >> 12) & 0x0F);
            utf8_str[j++] = 0x80 | ((unicode_char >> 6) & 0x3F);
            utf8_str[j++] = 0x80 | (unicode_char & 0x3F);
        }
        i += 2;
    }
    utf8_str[j] = '\0';
}

void print_hex(const unsigned char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (size % 16 != 0)
        printf("\n");
}

void print_dir_entry(const unsigned char *entry)
{
    printf("Directory Entry Content:\n");
    print_hex(entry, 32);
}

void print_fat_entries(FILE *fat_file, unsigned int fat_start, unsigned int fat_size, unsigned char fats, unsigned int cluster, unsigned short sector_size)
{
    unsigned int fat_offset = fat_start + cluster * 4;
    unsigned char fat_entry_bytes[4];
    for (int i = 0; i < fats; i++)
    {
        fseek(fat_file, fat_offset + i * fat_size * sector_size, SEEK_SET);
        fread(fat_entry_bytes, 1, 4, fat_file);
        unsigned int fat_entry = read_le32(fat_entry_bytes) & 0x0FFFFFFF;
        printf("FAT[%u] in FAT%d: %08X\n", cluster, i + 1, fat_entry);
    }
}

void get_short_name(DirEntry *dir_entry, char *short_name)
{
    char name[9] = {0};
    char ext[4] = {0};
    memcpy(name, dir_entry->name, 8);
    memcpy(ext, dir_entry->name + 8, 3);
    for (int i = 7; i >= 0; i--)
    {
        if (name[i] == ' ')
            name[i] = '\0';
        else
            break;
    }
    for (int i = 2; i >= 0; i--)
    {
        if (ext[i] == ' ')
            ext[i] = '\0';
        else
            break;
    }
    if (strlen(ext) > 0)
        sprintf(short_name, "%s.%s", name, ext);
    else
        strcpy(short_name, name);
}

int match_filename(const char *filename1, const char *filename2)
{
    return strcmp(filename1, filename2) == 0;
}

int split_path(const char *path, char components[][256])
{
    int count = 0;
    char temp[1024];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';
    char *start = temp;
    if (temp[0] == '/')
        start = temp + 1;
    char *token = strtok(start, "/");
    while (token != NULL && count < MAX_PATH_COMPONENTS)
    {
        strncpy(components[count++], token, 255);
        components[count - 1][255] = '\0';
        token = strtok(NULL, "/");
    }
    return count;
}

void read_long_name_entries(FILE *fat_file, unsigned int offset, char *long_name)
{
    LongDirEntry ldir;
    char temp_name[256] = {0};
    int entry_count = 0;
    while (1)
    {
        fseek(fat_file, offset - entry_count * sizeof(LongDirEntry), SEEK_SET);
        fread(&ldir, sizeof(LongDirEntry), 1, fat_file);
        if (ldir.attr != 0x0F)
            break;
        unsigned char utf16le_name[26];
        memcpy(utf16le_name, ldir.name1, 10);
        memcpy(utf16le_name + 10, ldir.name2, 12);
        memcpy(utf16le_name + 22, ldir.name3, 4);
        char utf8_name[14];
        utf16le_to_utf8(utf16le_name, 26, utf8_name, 14);
        strcat(temp_name, utf8_name);
        entry_count++;
        if (ldir.ord & 0x40)
            break;
    }
    strcpy(long_name, temp_name);
}

unsigned int find_file_in_directory(FILE *fat_file, const char *filename, unsigned short sector_size,
                                    unsigned short reserved_sectors, unsigned int fat_size,
                                    unsigned int cluster, unsigned short sec_per_clus,
                                    FATBootSector *boot_sector, unsigned int *file_size,
                                    unsigned int *dir_entry_offset, int traverse_subdirs)
{
    unsigned int cluster_size = sector_size * sec_per_clus;
    unsigned int data_start = (reserved_sectors + boot_sector->fats * fat_size) * sector_size;
    unsigned int dir_start = data_start + (cluster - 2) * cluster_size;
    if (fseek(fat_file, dir_start, SEEK_SET) != 0)
    {
        perror("fseek failed");
        return 0;
    }
    DirEntry dir_entry;
    char long_name[256] = {0};
    while (fread(&dir_entry, sizeof(DirEntry), 1, fat_file) == 1)
    {
        if (dir_entry.name[0] == 0x00)
            break;
        if (dir_entry.name[0] == 0xE5)
            continue;
        if (dir_entry.attr == 0x0F)
        {
            LongDirEntry ldir;
            memcpy(&ldir, &dir_entry, sizeof(LongDirEntry));
            int name_offset = ((ldir.ord & 0x3F) - 1) * 13;
            for (int i = 0; i < 5; i++)
                long_name[name_offset + i] = ldir.name1[i * 2];
            for (int i = 0; i < 6; i++)
                long_name[name_offset + 5 + i] = ldir.name2[i * 2];
            for (int i = 0; i < 2; i++)
                long_name[name_offset + 11 + i] = ldir.name3[i * 2];
            continue;
        }
        else
        {
            if (long_name[0] != '\0')
            {
                if (match_filename(filename, long_name))
                {
                    unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                    unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                    unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                    *file_size = read_le32(dir_entry.file_size);
                    *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                    return start_cluster;
                }
                long_name[0] = '\0';
                if (dir_entry.attr & 0x10 && !(dir_entry.attr & 0x08) && traverse_subdirs)
                {
                    unsigned int subdir_cluster = (read_le16(dir_entry.fstClusHI) << 16) | read_le16(dir_entry.fstClusLO);
                    if (strncmp((char *)dir_entry.name, ".          ", 11) != 0 && strncmp((char *)dir_entry.name, "..         ", 11) != 0)
                    {
                        unsigned int result = find_file_in_directory(fat_file, filename, sector_size,
                                                                     reserved_sectors, fat_size, subdir_cluster,
                                                                     sec_per_clus, boot_sector, file_size, dir_entry_offset, traverse_subdirs);
                        if (result != 0)
                            return result;
                    }
                }
            }
            else
            {
                char short_name[13];
                get_short_name(&dir_entry, short_name);
                if (match_filename(filename, short_name))
                {
                    unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                    unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                    unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                    *file_size = read_le32(dir_entry.file_size);
                    *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                    return start_cluster;
                }
                if (dir_entry.attr & 0x10 && !(dir_entry.attr & 0x08) && traverse_subdirs)
                {
                    unsigned int subdir_cluster = (read_le16(dir_entry.fstClusHI) << 16) | read_le16(dir_entry.fstClusLO);
                    if (strncmp((char *)dir_entry.name, ".          ", 11) != 0 && strncmp((char *)dir_entry.name, "..         ", 11) != 0)
                    {
                        unsigned int result = find_file_in_directory(fat_file, filename, sector_size,
                                                                     reserved_sectors, fat_size, subdir_cluster,
                                                                     sec_per_clus, boot_sector, file_size, dir_entry_offset, traverse_subdirs);
                        if (result != 0)
                            return result;
                    }
                }
            }
        }
    }
    return 0;
}

unsigned int find_file_by_path(FILE *fat_file, char path[][256], int path_count,
                               unsigned short sector_size, unsigned short reserved_sectors, unsigned int fat_size,
                               unsigned short sec_per_clus, FATBootSector *boot_sector, unsigned int *file_size, unsigned int *dir_entry_offset)
{
    unsigned int current_cluster = boot_sector->fat32.root_cluster;
    int traverse_subdirs = 0;
    if (path_count > 1)
        traverse_subdirs = 1;
    for (int i = 0; i < path_count; i++)
    {
        unsigned int found_cluster = find_file_in_directory(fat_file, path[i], sector_size, reserved_sectors, fat_size,
                                                            current_cluster, sec_per_clus, boot_sector, file_size, dir_entry_offset, traverse_subdirs);
        if (found_cluster == 0)
            return 0;
        current_cluster = found_cluster;
    }
    return current_cluster;
}

void read_file_content(FILE *fat_file, FATBootSector *boot_sector, unsigned int start_cluster, unsigned int file_size)
{
    unsigned short sector_size = read_le16(boot_sector->sector_size);
    unsigned int fat_size = boot_sector->fat32.length;
    unsigned char fats = boot_sector->fats;
    unsigned short reserved_sectors = boot_sector->reserved;
    unsigned int fat_start = reserved_sectors * sector_size;
    unsigned int data_start = (reserved_sectors + fats * fat_size) * sector_size;
    unsigned int cluster_size = boot_sector->sec_per_clus * sector_size;
    unsigned int next_cluster = start_cluster;
    unsigned int bytes_read = 0;
    printf("File Content\n");
    while (next_cluster < 0x0FFFFFF8 && bytes_read < file_size)
    {
        unsigned int cluster_offset = data_start + (next_cluster - 2) * cluster_size;
        unsigned int bytes_to_read = (file_size - bytes_read > cluster_size) ? cluster_size : (file_size - bytes_read);
        unsigned char *buffer = (unsigned char *)malloc(bytes_to_read);
        if (buffer)
        {
            if (fseek(fat_file, cluster_offset, SEEK_SET) != 0)
            {
                perror("fseek failed");
                free(buffer);
                return;
            }
            size_t read = fread(buffer, 1, bytes_to_read, fat_file);
            if (read != bytes_to_read)
            {
                perror("fread failed");
                free(buffer);
                return;
            }
            fwrite(buffer, 1, read, stdout);
            free(buffer);
            bytes_read += read;
        }
        else
        {
            perror("Memory allocation failed");
            return;
        }
        unsigned int fat_offset = fat_start + next_cluster * 4;
        unsigned char fat_entry_bytes[4];
        if (fseek(fat_file, fat_offset, SEEK_SET) != 0)
        {
            perror("fseek failed");
            return;
        }
        size_t fat_read = fread(fat_entry_bytes, 1, 4, fat_file);
        if (fat_read != 4)
        {
            perror("fread failed");
            return;
        }
        unsigned int fat_entry = read_le32(fat_entry_bytes) & 0x0FFFFFFF;
        next_cluster = fat_entry;
    }
    printf("\nEOF\n");
}

void delete_file(FILE *fat_file, FATBootSector *boot_sector, unsigned int start_cluster,
                 unsigned int file_size, unsigned int dir_entry_offset, const char *target_filename)
{
    unsigned short sector_size = read_le16(boot_sector->sector_size);
    unsigned int fat_size = boot_sector->fat32.length;
    unsigned char fats = boot_sector->fats;
    unsigned short reserved_sectors = boot_sector->reserved;
    unsigned int fat_start = reserved_sectors * sector_size;
    unsigned int data_start = (reserved_sectors + fats * fat_size) * sector_size;
    unsigned int cluster_size = boot_sector->sec_per_clus * sector_size;
    unsigned int next_cluster = start_cluster;
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
    {
        perror("/dev/urandom failed to open");
        return;
    }
    unsigned int cluster_chain[10000];
    int chain_length = 0;
    while (next_cluster < 0x0FFFFFF8 && chain_length < 10000)
    {
        cluster_chain[chain_length++] = next_cluster;
        unsigned int fat_offset = fat_start + next_cluster * 4;
        unsigned char fat_entry_bytes[4];
        fseek(fat_file, fat_offset, SEEK_SET);
        fread(fat_entry_bytes, 1, 4, fat_file);
        unsigned int fat_entry = read_le32(fat_entry_bytes) & 0x0FFFFFFF;
        if (fat_entry == 0x0FFFFFFF || fat_entry == 0x0FFFFFF8)
            break;
        next_cluster = fat_entry;
    }
    unsigned char dir_entry_content_before[32];
    fseek(fat_file, dir_entry_offset, SEEK_SET);
    fread(dir_entry_content_before, 1, 32, fat_file);
    printf("\n=== Directory Entry Before Deletion ===\n");
    print_dir_entry(dir_entry_content_before);
    printf("\n=== File Content Before Deletion ===\n");
    read_file_content(fat_file, boot_sector, start_cluster, file_size);
    printf("\n=== FAT Table Before Deletion ===\n");
    for (int i = 0; i < chain_length; i++)
    {
        printf("Cluster %u:\n", cluster_chain[i]);
        print_fat_entries(fat_file, fat_start, fat_size, fats, cluster_chain[i], sector_size);
    }
    printf("\n=== Overwriting File Data ===\n");
    unsigned int bytes_to_wipe = file_size;
    unsigned int wiped_bytes = 0;
    for (int pass = 1; pass <= NUM_PASSES; pass++)
    {
        printf("Overwriting pass %d/%d\n", pass, NUM_PASSES);
        for (int i = 0; i < chain_length && wiped_bytes < bytes_to_wipe; i++)
        {
            unsigned int cluster_offset = data_start + (cluster_chain[i] - 2) * cluster_size;
            fseek(fat_file, cluster_offset, SEEK_SET);
            unsigned int bytes_remaining = bytes_to_wipe - wiped_bytes;
            unsigned int bytes_this_cluster = (bytes_remaining < cluster_size) ? bytes_remaining : cluster_size;
            unsigned char *random_buffer = (unsigned char *)malloc(bytes_this_cluster);
            if (random_buffer)
            {
                size_t read_bytes = fread(random_buffer, 1, bytes_this_cluster, urandom);
                if (read_bytes != bytes_this_cluster)
                {
                    perror("Failed to read random data");
                    free(random_buffer);
                    fclose(urandom);
                    return;
                }
                fseek(fat_file, cluster_offset, SEEK_SET);
                fwrite(random_buffer, 1, bytes_this_cluster, fat_file);
                free(random_buffer);
                wiped_bytes += bytes_this_cluster;
            }
            else
            {
                perror("Memory allocation failed");
                fclose(urandom);
                return;
            }
        }
        wiped_bytes = 0;
    }
    fclose(urandom);
    printf("Data overwriting completed.\n");
    printf("\n=== File Content After Overwriting ===\n");
    read_file_content(fat_file, boot_sector, start_cluster, file_size);
    printf("\n=== FAT Table After Overwriting ===\n");
    for (int i = 0; i < chain_length; i++)
    {
        printf("Cluster %u:\n", cluster_chain[i]);
        print_fat_entries(fat_file, fat_start, fat_size, fats, cluster_chain[i], sector_size);
    }
    printf("\n=== Clearing FAT Entries ===\n");
    for (int i = 0; i < chain_length; i++)
    {
        unsigned int fat_offset = fat_start + cluster_chain[i] * 4;
        unsigned char zero[4] = {0};
        for (int j = 0; j < fats; j++)
        {
            fseek(fat_file, fat_offset + j * fat_size * sector_size, SEEK_SET);
            fwrite(zero, 1, 4, fat_file);
            printf("FAT[%u] in FAT%d set to 0x00000000\n", cluster_chain[i], j + 1);
        }
    }
    printf("\n=== Deleting Directory Entry ===\n");
    unsigned int offset = dir_entry_offset;
    DirEntry dir_entry;
    fseek(fat_file, offset, SEEK_SET);
    fread(&dir_entry, sizeof(DirEntry), 1, fat_file);
    if ((dir_entry.attr & 0x0F) == 0x0F)
    {
    }
    else
    {
        unsigned char ord;
        do
        {
            offset -= sizeof(DirEntry);
            if (fseek(fat_file, offset, SEEK_SET) != 0)
            {
                perror("fseek failed while searching LFN entries");
                break;
            }
            fread(&dir_entry, sizeof(DirEntry), 1, fat_file);
            ord = dir_entry.name[0];
            unsigned char delete_marker = 0xE5;
            fseek(fat_file, offset, SEEK_SET);
            if (fwrite(&delete_marker, 1, 1, fat_file) != 1)
            {
                perror("Failed to write delete marker");
                break;
            }
            unsigned char zeros[31] = {0};
            if (fwrite(zeros, 1, 31, fat_file) != 31)
            {
                perror("Failed to write zero bytes");
                break;
            }
            printf("LFN directory entry at offset %u marked as deleted.\n", offset);
        } while ((ord & 0x40) == 0 && (dir_entry.attr == 0x0F));
        fseek(fat_file, dir_entry_offset, SEEK_SET);
    }
    unsigned char delete_marker = 0xE5;
    fseek(fat_file, dir_entry_offset, SEEK_SET);
    if (fwrite(&delete_marker, 1, 1, fat_file) != 1)
    {
        perror("Failed to write delete marker");
    }
    unsigned char zeros[31] = {0};
    if (fwrite(zeros, 1, 31, fat_file) != 31)
    {
        perror("Failed to write zero bytes");
    }
    printf("Primary directory entry at offset %u marked as deleted.\n", dir_entry_offset);
    unsigned char dir_entry_content_after[32];
    fseek(fat_file, dir_entry_offset, SEEK_SET);
    fread(dir_entry_content_after, 1, 32, fat_file);
    printf("\n=== Directory Entry After Deletion ===\n");
    print_dir_entry(dir_entry_content_after);
    printf("\n=== FAT Table After Deletion ===\n");
    for (int i = 0; i < chain_length; i++)
    {
        printf("Cluster %u:\n", cluster_chain[i]);
        print_fat_entries(fat_file, fat_start, fat_size, fats, cluster_chain[i], sector_size);
    }
    printf("\nFile \"%s\" has been completely deleted.\n", target_filename);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <device path> <file path>\n", argv[0]);
        return 1;
    }
    char *device_path = argv[1];
    char *file_path = argv[2];
    FILE *fat_file = fopen(device_path, "rb+");
    if (!fat_file)
    {
        perror("Unable to open FAT32 partition");
        return 1;
    }
    char path_components[MAX_PATH_COMPONENTS][256];
    int path_count = split_path(file_path, path_components);
    if (path_count == 0)
    {
        printf("Invalid file path.\n");
        fclose(fat_file);
        return 1;
    }
    FATBootSector boot_sector;
    fread(&boot_sector, sizeof(FATBootSector), 1, fat_file);
    printf("System ID: %.8s\n", boot_sector.system_id);
    printf("Bytes per sector: %u\n", read_le16(boot_sector.sector_size));
    printf("Sectors per cluster: %u\n", boot_sector.sec_per_clus);
    printf("Reserved sectors: %u\n", boot_sector.reserved);
    printf("Number of FATs: %u\n", boot_sector.fats);
    printf("Total sectors (32-bit): %u\n", boot_sector.total_sect);
    printf("FAT size (32-bit): %u\n", boot_sector.fat32.length);
    printf("Root directory cluster: %u\n", boot_sector.fat32.root_cluster);
    printf("Volume label: %.11s\n", boot_sector.fat32.vol_label);
    printf("File system type: %.8s\n", boot_sector.fat32.fs_type);
    unsigned short sector_size = read_le16(boot_sector.sector_size);
    unsigned short reserved_sectors = boot_sector.reserved;
    unsigned int fat_size = boot_sector.fat32.length;
    unsigned short sec_per_clus = boot_sector.sec_per_clus;
    unsigned int file_size;
    unsigned int dir_entry_offset;
    unsigned int start_cluster = find_file_by_path(fat_file, path_components, path_count,
                                                   sector_size, reserved_sectors, fat_size,
                                                   sec_per_clus, &boot_sector, &file_size, &dir_entry_offset);
    if (start_cluster != 0)
    {
        printf("File \"%s\" found, starting deletion...\n", file_path);
        delete_file(fat_file, &boot_sector, start_cluster, file_size, dir_entry_offset, file_path);
    }
    else
        printf("File \"%s\" not found.\n", file_path);
    fclose(fat_file);
    return 0;
}