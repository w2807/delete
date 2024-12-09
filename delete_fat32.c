#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_PASSES 3
#define MAX_PATH_COMPONENTS 256

#ifdef DEBUG
#define PRINT_DEBUG(...) printf(__VA_ARGS__)
#else
#define PRINT_DEBUG(...)
#endif

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

unsigned short read_le16(const unsigned char *bytes);
unsigned int read_le32(const unsigned char *bytes);
void print_hex(const unsigned char *buffer, size_t size);
void print_dir_entry(const unsigned char *entry);
void print_fat_entries(FILE *fat_file, unsigned int fat_start, unsigned int fat_size, unsigned char fats, unsigned int cluster, unsigned short sector_size);
void get_short_name(DirEntry *dir_entry, char *short_name);
int match_filename(const char *filename1, const char *filename2);
int split_path(const char *path, char components[][256]);
unsigned int find_file_in_directory(FILE *fat_file, const char *filename, unsigned short sector_size,
                                    unsigned short reserved_sectors, unsigned int fat_size,
                                    unsigned int cluster, unsigned short sec_per_clus,
                                    FATBootSector *boot_sector, unsigned int *file_size,
                                    unsigned int *dir_entry_offset, int traverse_subdirs);
unsigned int find_file_by_path(FILE *fat_file, char path[][256], int path_count,
                               unsigned short sector_size, unsigned short reserved_sectors, unsigned int fat_size,
                               unsigned short sec_per_clus, FATBootSector *boot_sector, unsigned int *file_size, unsigned int *dir_entry_offset);
void read_file_content(FILE *fat_file, FATBootSector *boot_sector, unsigned int start_cluster, unsigned int file_size);
void delete_file(FILE *fat_file, FATBootSector *boot_sector, unsigned int start_cluster,
                 unsigned int file_size, unsigned int dir_entry_offset, const char *target_filename);

unsigned short read_le16(const unsigned char *bytes)
{
    return (unsigned short)(bytes[0] | (bytes[1] << 8));
}

unsigned int read_le32(const unsigned char *bytes)
{
    return (unsigned int)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
}

void print_hex(const unsigned char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        PRINT_DEBUG("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0)
            PRINT_DEBUG("\n");
    }
    if (size % 16 != 0)
        PRINT_DEBUG("\n");
}

void print_dir_entry(const unsigned char *entry)
{
    PRINT_DEBUG("Directory Entry Content:\n");
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
#ifdef DEBUG
        unsigned int fat_entry = read_le32(fat_entry_bytes) & 0x0FFFFFFF;
#endif
        PRINT_DEBUG("FAT[%u] in FAT%d: %08X\n", cluster, i + 1, fat_entry);
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

unsigned int find_file_in_directory(FILE *fat_file, const char *filename, unsigned short sector_size,
                                    unsigned short reserved_sectors, unsigned int fat_size,
                                    unsigned int cluster, unsigned short sec_per_clus,
                                    FATBootSector *boot_sector, unsigned int *file_size,
                                    unsigned int *dir_entry_offset, int is_last_component)
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
                    if ((is_last_component && !(dir_entry.attr & 0x10)) ||
                        (!is_last_component && (dir_entry.attr & 0x10)))
                    {
                        unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                        unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                        unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                        *file_size = read_le32(dir_entry.file_size);
                        *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                        return start_cluster;
                    }
                }
                long_name[0] = '\0';
            }
            else
            {
                char short_name[13];
                get_short_name(&dir_entry, short_name);
                if (match_filename(filename, short_name))
                {
                    if ((is_last_component && !(dir_entry.attr & 0x10)) ||
                        (!is_last_component && (dir_entry.attr & 0x10)))
                    {
                        unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                        unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                        unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                        *file_size = read_le32(dir_entry.file_size);
                        *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                        return start_cluster;
                    }
                }
            }
        }
    }
    return 0;
}

unsigned int find_file_by_path(FILE *fat_file, char path[][256], int path_count,
                               unsigned short sector_size, unsigned short reserved_sectors,
                               unsigned int fat_size, unsigned short sec_per_clus,
                               FATBootSector *boot_sector, unsigned int *file_size,
                               unsigned int *dir_entry_offset)
{
    unsigned int current_cluster = boot_sector->fat32.root_cluster;
    for (int i = 0; i < path_count; i++)
    {
        unsigned int found_cluster = find_file_in_directory(fat_file, path[i],
                                                            sector_size, reserved_sectors,
                                                            fat_size, current_cluster,
                                                            sec_per_clus, boot_sector,
                                                            file_size, dir_entry_offset,
                                                            i == path_count - 1);
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
    PRINT_DEBUG("File Content\n");
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
#ifdef DEBUG
            fwrite(buffer, 1, read, stdout);
#endif
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
    PRINT_DEBUG("\nEOF\n");
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
    PRINT_DEBUG("\nDirectory Entry Before Deletion:\n");
    print_dir_entry(dir_entry_content_before);
    PRINT_DEBUG("\nFile Content Before Deletion:\n");
    read_file_content(fat_file, boot_sector, start_cluster, file_size);
    PRINT_DEBUG("\nFAT Table Before Deletion:\n");
    for (int i = 0; i < chain_length; i++)
    {
        PRINT_DEBUG("Cluster %u:\n", cluster_chain[i]);
        print_fat_entries(fat_file, fat_start, fat_size, fats, cluster_chain[i], sector_size);
    }
    PRINT_DEBUG("\nOverwriting File Data:\n");
    unsigned int bytes_to_wipe = file_size;
    unsigned int wiped_bytes = 0;
    for (int pass = 1; pass <= NUM_PASSES; pass++)
    {
        PRINT_DEBUG("Overwriting pass %d/%d\n", pass, NUM_PASSES);
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
    PRINT_DEBUG("Data overwriting completed.\n");
    PRINT_DEBUG("\nFile Content After Overwriting:\n");
    read_file_content(fat_file, boot_sector, start_cluster, file_size);
    PRINT_DEBUG("\n:FAT Table After Overwriting:\n");
    for (int i = 0; i < chain_length; i++)
    {
        PRINT_DEBUG("Cluster %u:\n", cluster_chain[i]);
        print_fat_entries(fat_file, fat_start, fat_size, fats, cluster_chain[i], sector_size);
    }
    PRINT_DEBUG("\nClear FAT Entries:\n");
    for (int i = 0; i < chain_length; i++)
    {
        unsigned int fat_offset = fat_start + cluster_chain[i] * 4;
        unsigned char zero[4] = {0};
        for (int j = 0; j < fats; j++)
        {
            fseek(fat_file, fat_offset + j * fat_size * sector_size, SEEK_SET);
            fwrite(zero, 1, 4, fat_file);
            PRINT_DEBUG("FAT[%u] in FAT%d set to 0x00000000\n", cluster_chain[i], j + 1);
        }
    }
    PRINT_DEBUG("\nDeleting Directory Entry:\n");
    unsigned int offset = dir_entry_offset;
    DirEntry dir_entry;
    int has_lfn = 0;
    unsigned int check_offset = offset;
    while (check_offset >= sizeof(DirEntry))
    {
        check_offset -= sizeof(DirEntry);
        if (fseek(fat_file, check_offset, SEEK_SET) != 0)
            break;
        if (fread(&dir_entry, sizeof(DirEntry), 1, fat_file) != 1)
            break;
        if ((dir_entry.attr & 0x0F) == 0x0F)
        {
            has_lfn = 1;
            break;
        }
        else
            break;
    }
    if (has_lfn)
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
            if (fread(&dir_entry, sizeof(DirEntry), 1, fat_file) != 1)
                break;
            ord = dir_entry.name[0];
            if ((dir_entry.attr & 0x0F) == 0x0F)
            {
                unsigned char delete_marker = 0xE5;
                fseek(fat_file, offset, SEEK_SET);
                if (fwrite(&delete_marker, 1, 1, fat_file) != 1)
                {
                    perror("Failed to delete LFN entry");
                    break;
                }
                unsigned char zeros[31] = {0};
                if (fwrite(zeros, 1, sizeof(zeros), fat_file) != sizeof(zeros))
                {
                    perror("Failed to write zeros to LFN entry");
                    break;
                }
            }
        } while ((ord & 0x40) == 0 && (dir_entry.attr & 0x0F) == 0x0F);
    }
    fseek(fat_file, dir_entry_offset, SEEK_SET);
    unsigned char delete_marker = 0xE5;
    if (fwrite(&delete_marker, 1, 1, fat_file) != 1)
        perror("Failed to delete primary directory entry");
    unsigned char zeros[31] = {0};
    if (fwrite(zeros, 1, sizeof(zeros), fat_file) != sizeof(zeros))
        perror("Failed to write zeros to primary directory entry");
    PRINT_DEBUG("directory entry at offset 0x%x deleted.\n", dir_entry_offset);
    unsigned char dir_entry_content_after[32];
    fseek(fat_file, dir_entry_offset, SEEK_SET);
    fread(dir_entry_content_after, 1, 32, fat_file);
    PRINT_DEBUG("\nDirectory Entry After Deletion:\n");
    print_dir_entry(dir_entry_content_after);
    PRINT_DEBUG("\nFAT Table After Deletion:\n");
    for (int i = 0; i < chain_length; i++)
    {
        PRINT_DEBUG("Cluster %u:\n", cluster_chain[i]);
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
    PRINT_DEBUG("System ID: %.8s\n", boot_sector.system_id);
    PRINT_DEBUG("Bytes per sector: %u\n", read_le16(boot_sector.sector_size));
    PRINT_DEBUG("Sectors per cluster: %u\n", boot_sector.sec_per_clus);
    PRINT_DEBUG("Reserved sectors: %u\n", boot_sector.reserved);
    PRINT_DEBUG("Number of FATs: %u\n", boot_sector.fats);
    PRINT_DEBUG("Total sectors: %u\n", boot_sector.total_sect);
    PRINT_DEBUG("FAT size: %u\n", boot_sector.fat32.length);
    PRINT_DEBUG("Root directory cluster: %u\n", boot_sector.fat32.root_cluster);
    PRINT_DEBUG("Volume label: %.11s\n", boot_sector.fat32.vol_label);
    PRINT_DEBUG("File system type: %.8s\n", boot_sector.fat32.fs_type);
    PRINT_DEBUG("FAT1 offset: %u\n", boot_sector.reserved * read_le16(boot_sector.sector_size));
    PRINT_DEBUG("Root directory offset: %u\n", (boot_sector.reserved + boot_sector.fats * boot_sector.fat32.length) *
                                                       read_le16(boot_sector.sector_size) +
                                                   (boot_sector.fat32.root_cluster - 2) *
                                                       boot_sector.sec_per_clus * read_le16(boot_sector.sector_size));
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
        printf("File \"%s\" found\n", file_path);
        delete_file(fat_file, &boot_sector, start_cluster, file_size, dir_entry_offset, file_path);
    }
    else
        printf("File \"%s\" not found.\n", file_path);
    fclose(fat_file);
    return 0;
}