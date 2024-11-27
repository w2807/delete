#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_PATH_COMPONENTS 256

// FAT Boot Sector结构
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

// 目录项结构
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

// 长目录项结构
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

// 读取小端16位
unsigned short read_le16(const unsigned char *bytes)
{
    return (unsigned short)(bytes[0] | (bytes[1] << 8));
}

// 读取小端32位
unsigned int read_le32(const unsigned char *bytes)
{
    return (unsigned int)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
}

// 不区分大小写比较
int match_long_filename(const char *filename, const char *long_name)
{
    return strcasecmp(filename, long_name) == 0;
}

// 获取短文件名并转换为大写
void get_short_name(DirEntry *dir_entry, char *short_name)
{
    char name[9] = {0};
    char ext[4] = {0};
    memcpy(name, dir_entry->name, 8);
    memcpy(ext, dir_entry->name + 8, 3);
    // 去除末尾的空格
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

    // 转换为大写，确保匹配不区分大小写
    for (int i = 0; short_name[i]; i++) {
        short_name[i] = toupper((unsigned char)short_name[i]);
    }
}

// 分割路径为组件，忽略前导斜杠
int split_path(const char *path, char components[][256])
{
    int count = 0;
    char temp[1024];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';

    // 忽略前导斜杠
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

// 查找目录中的特定项
unsigned int find_file_in_directory(FILE *fat_file, const char *filename,
                                    unsigned short sector_size, unsigned short reserved_sectors, unsigned int fat_size,
                                    unsigned int cluster, unsigned short sec_per_clus,
                                    FATBootSector *boot_sector, unsigned int *file_size, unsigned int *dir_entry_offset,
                                    int traverse_subdirs)
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
            {
                long_name[name_offset + i] = ldir.name1[i * 2];
            }
            for (int i = 0; i < 6; i++)
            {
                long_name[name_offset + 5 + i] = ldir.name2[i * 2];
            }
            for (int i = 0; i < 2; i++)
            {
                long_name[name_offset + 11 + i] = ldir.name3[i * 2];
            }
            continue;
        }
        else
        {
            if (long_name[0] != '\0')
            {
                if (match_long_filename(filename, long_name))
                {
                    unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                    unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                    unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                    *file_size = read_le32(dir_entry.file_size);
                    *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                    return start_cluster;
                }
                long_name[0] = '\0';
                if (dir_entry.attr & 0x10 && !(dir_entry.attr & 0x08) && traverse_subdirs) // 目录且不是卷标
                {
                    unsigned int subdir_cluster = (read_le16(dir_entry.fstClusHI) << 16) | read_le16(dir_entry.fstClusLO);
                    // 排除 "." 和 ".." 目录
                    if (strncmp((char*)dir_entry.name, ".          ", 11) != 0 && strncmp((char*)dir_entry.name, "..         ", 11) != 0)
                    {
                        unsigned int result = find_file_in_directory(fat_file, filename, sector_size,
                                                                     reserved_sectors, fat_size, subdir_cluster, sec_per_clus, boot_sector, file_size, dir_entry_offset, traverse_subdirs);
                        if (result != 0)
                            return result;
                    }
                }
            }
            else
            {
                char short_name[13];
                get_short_name(&dir_entry, short_name);
                if (match_long_filename(filename, short_name))
                {
                    unsigned int fstClusHI = read_le16(dir_entry.fstClusHI);
                    unsigned int fstClusLO = read_le16(dir_entry.fstClusLO);
                    unsigned int start_cluster = (fstClusHI << 16) | fstClusLO;
                    *file_size = read_le32(dir_entry.file_size);
                    *dir_entry_offset = ftell(fat_file) - sizeof(DirEntry);
                    return start_cluster;
                }
                // 如果是目录，继续搜索
                if (dir_entry.attr & 0x10 && !(dir_entry.attr & 0x08) && traverse_subdirs) // 目录且不是卷标
                {
                    unsigned int subdir_cluster = (read_le16(dir_entry.fstClusHI) << 16) | read_le16(dir_entry.fstClusLO);
                    // 排除 "." 和 ".." 目录
                    if (strncmp((char*)dir_entry.name, ".          ", 11) != 0 && strncmp((char*)dir_entry.name, "..         ", 11) != 0)
                    {
                        unsigned int result = find_file_in_directory(fat_file, filename, sector_size,
                                                                     reserved_sectors, fat_size, subdir_cluster, sec_per_clus, boot_sector, file_size, dir_entry_offset, traverse_subdirs);
                        if (result != 0)
                            return result;
                    }
                }
            }
        }
    }
    return 0;
}

// 根据路径查找文件
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

// 读取并显示文件内容
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

    printf("=== 文件内容 ===\n");
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
        // 读取下一个簇
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
    printf("\n=== 文件结束 ===\n");
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

    // 分割路径
    char path_components[MAX_PATH_COMPONENTS][256];
    int path_count = split_path(file_path, path_components);
    if (path_count == 0)
    {
        printf("Invalid file path.\n");
        return 1;
    }

    FILE *fat_file = fopen(device_path, "rb");
    if (!fat_file)
    {
        perror("Cannot open FAT32 partition");
        return 1;
    }

    FATBootSector boot_sector;
    size_t boot_read = fread(&boot_sector, sizeof(FATBootSector), 1, fat_file);
    if (boot_read != 1)
    {
        perror("Failed to read boot sector");
        fclose(fat_file);
        return 1;
    }

    printf("System ID: %.8s\n", boot_sector.system_id);
    printf("Bytes per sector: %u\n", read_le16(boot_sector.sector_size));
    printf("Sectors per cluster: %u\n", boot_sector.sec_per_clus);
    printf("Reserved sectors: %u\n", boot_sector.reserved);
    printf("Number of FATs: %u\n", boot_sector.fats);
    printf("Total sectors (32): %u\n", boot_sector.total_sect);
    printf("FAT size (32): %u\n", boot_sector.fat32.length);
    printf("Root cluster: %u\n", boot_sector.fat32.root_cluster);
    printf("Volume label: %.11s\n", boot_sector.fat32.vol_label);
    printf("Filesystem type: %.8s\n", boot_sector.fat32.fs_type);

    unsigned short sector_size = read_le16(boot_sector.sector_size);
    unsigned short reserved_sectors = boot_sector.reserved;
    unsigned int fat_size = boot_sector.fat32.length;
    unsigned short sec_per_clus = boot_sector.sec_per_clus;
    unsigned int file_size;
    unsigned int dir_entry_offset;

    unsigned int start_cluster = find_file_by_path(fat_file, path_components, path_count,
                                                  sector_size, reserved_sectors, fat_size, sec_per_clus, &boot_sector, &file_size, &dir_entry_offset);
    if (start_cluster != 0)
    {
        printf("File found. Content:\n");
        read_file_content(fat_file, &boot_sector, start_cluster, file_size);
    }
    else
    {
        // 判断是否需要遍历子目录
        if (path_count > 1)
        {
            printf("文件未找到。\n");
        }
        else
        {
            printf("文件未找到。\n");
        }
    }

    fclose(fat_file);
    return 0;
}