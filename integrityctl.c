#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <sqlite3.h>

#include "sds.h"

unsigned char md5digest[MD5_DIGEST_LENGTH];
unsigned char md5hex[MD5_DIGEST_LENGTH * 2 + 1];
sqlite3 *db;
sqlite3_stmt *stmt;
sqlite3_stmt *deleted_stmt;
int recursive = 0;
int save = 0;
int check = 0;

const char *init_sql = "\
CREATE TABLE IF NOT EXISTS integrity (\n\
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
    name TEXT NOT NULL,\n\
    type TINYINT NOT NULL DEFAULT 0,\n\
    parent_id INTEGER REFERENCES integrity(id) ON DELETE CASCADE,\n\
    md5 TEXT(32) NOT NULL DEFAULT ''\n\
);\n\
CREATE UNIQUE INDEX IF NOT EXISTS filename ON integrity(name, parent_id);\
";
const char *insert_sql = "INSERT INTO integrity (name, type, parent_id, md5) VALUES (?, ?, ?, ?);";
const char *get_file_sql = "SELECT id, type, md5 FROM integrity WHERE name = ? AND parent_id = ?;";
const char *find_deleted_sql = "SELECT name FROM integrity WHERE parent_id = ?;";

void md5_to_hex()
{
    static char *hex_digist = "0123456789abcdef";
    for (int hex_i = 0, i = 0; i < MD5_DIGEST_LENGTH; hex_i += 2, i++)
    {
        md5hex[hex_i] = hex_digist[md5digest[i] >> 4];
        md5hex[hex_i + 1] = hex_digist[md5digest[i] & 0xF];
    }
}

int file_hash(sds path)
{
    static char buff[4096];
    static MD5_CTX md5handler;

    MD5_Init(&md5handler);
    FILE *fd = fopen(path, "rb");
    if (fd == NULL)
        return 1;

    while (!feof(fd))
    {
        size_t count = fread(buff, 1, 4096, fd);
        MD5_Update(&md5handler, buff, count);
    }
    fclose(fd);

    MD5_Final(md5digest, &md5handler);
    md5_to_hex();

    return 0;
}

int str_equality(const unsigned char *str1, const unsigned char *str2, int len)
{
    int i;
    for (i = 0; i < len && str1[i] && str2[i] && str1[i] == str2[i]; i++)
        ;
    return str1[i] == str2[i];
}

void scan_dir(const sds path, const char *name, size_t parent_id)
{
    struct dirent *dp;
    DIR *dirp;
    size_t current_dir_id;

    if (save)
    {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, DT_DIR);
        sqlite3_bind_int64(stmt, 3, parent_id);
        sqlite3_bind_text(stmt, 4, "", -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(1);
        }
        current_dir_id = sqlite3_last_insert_rowid(db);
    }

    if (check)
    {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, parent_id);
        if (sqlite3_step(stmt) != SQLITE_ROW)
        {
            fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(1);
        }
        current_dir_id = sqlite3_column_int64(stmt, 0);
        sqlite3_reset(deleted_stmt);
        sqlite3_bind_int64(deleted_stmt, 1, current_dir_id);
        struct stat statbuf;
        while (sqlite3_step(deleted_stmt) == SQLITE_ROW)
        {
            sds file_for_check = sdscat(sdscat(sdsdup(path), "/"), (const char *)sqlite3_column_text(deleted_stmt, 0));
            if (stat(file_for_check, &statbuf) == -1)
            {
                printf("Removed file: %s\n\n", file_for_check);
            }
            sdsfree(file_for_check);
        }
    }
    dirp = opendir(path);
    while ((dp = readdir(dirp)) != NULL)
    {
        if (
            dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
            continue;
        sds new_path = sdscat(sdscat(sdsdup(path), "/"), dp->d_name);
        if (dp->d_type == DT_REG)
        {
            file_hash(new_path);
            if (save)
            {
                printf("%lu | %s | %s\n", dp->d_ino, md5hex, new_path);
                sqlite3_reset(stmt);
                sqlite3_bind_text(stmt, 1, dp->d_name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 2, DT_REG);
                sqlite3_bind_int64(stmt, 3, current_dir_id);
                sqlite3_bind_text(stmt, 4, (char *)md5hex, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) != SQLITE_DONE)
                {
                    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    exit(1);
                }
            }

            if (check)
            {
                sqlite3_reset(stmt);
                sqlite3_bind_text(stmt, 1, dp->d_name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 2, current_dir_id);
                if (sqlite3_step(stmt) != SQLITE_ROW)
                {
                    printf("New file: %s\n\n", new_path);
                    continue;
                }
                int type = sqlite3_column_int(stmt, 1);
                const unsigned char *stored_md5hex = sqlite3_column_text(stmt, 2);
                if (type != DT_REG)
                    printf("File changed (was a direcory): %s\n", new_path);
                if (!str_equality(md5hex, stored_md5hex, MD5_DIGEST_LENGTH * 2))
                    printf("Original| %s | %s\nChanged | %s | %s\n\n", md5hex, new_path, stored_md5hex, new_path);
            }
            continue;
        }
        if (dp->d_type == DT_DIR)
        {
            if (save)
                printf("%lu | ******************************** | %s/\n", dp->d_ino, new_path);
            if (check)
            {
                sqlite3_reset(stmt);
                sqlite3_bind_text(stmt, 1, dp->d_name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 2, current_dir_id);
                if (sqlite3_step(stmt) != SQLITE_ROW)
                {
                    printf("New directory: %s\n\n", new_path);
                    continue;
                }
                int type = sqlite3_column_int(stmt, 1);
                if (type != DT_DIR)
                {
                    printf("File changed (was a regular file): %s\n", new_path);
                    continue;
                }
            }
            if (recursive)
                scan_dir(new_path, dp->d_name, current_dir_id);
        }
        sdsfree(new_path);
    }
    closedir(dirp);
}

int main(int argc, char *argv[])
{
    char *db_path = NULL;
    char *zErrMsg = 0;
    md5hex[MD5_DIGEST_LENGTH * 2] = '\0';
    int option = 0;
    while ((option = getopt(argc, argv, "scrf:")) != -1)
    {
        switch (option)
        {
        case 's':
            save = 1;
            break;
        case 'c':
            check = 1;
            break;
        case 'r':
            recursive = 1;
            break;
        case 'f':
            db_path = optarg;
            break;
        }
    }

    if (check && save)
    {
        puts("You cannot check integrity and fill the integrity database at the same time.");
        return 1;
    }

    if (!check && !save)
    {
        puts("You must select 'save' or 'check' mode.");
        return 1;
    }

    if (check)
    {
        FILE *fd = fopen(db_path, "rb");
        if (!fd)
        {
            printf("Database file '%s' does not exists or you have not access permissions.\n", db_path);
            return 1;
        }
        fclose(fd);
    }

    if (save)
    {
        FILE *fd = fopen(db_path, "rb");
        if (fd)
        {
            fclose(fd);
            printf("Database file '%s' already exists. Please, remove it and start the program again.\n", db_path);
            return 1;
        }
    }
    char *rpath = realpath(argv[optind], NULL);
    if (rpath == NULL)
    {
        printf("Directory '%s' does not exists or is not a directory.", argv[optind]);
        return 1;
    }
    sds start_path = sdsnew(rpath);
    DIR *dirp = opendir(start_path);
    if (dirp == NULL)
    {
        printf("File '%s' cannot be opened as a directory.", start_path);
        exit(1);
    }
    closedir(dirp);
    sds name = sdsnew(basename(rpath));
    free(rpath);
    int rc = sqlite3_open(db_path, &db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    if (save)
    {
        rc = sqlite3_exec(db, init_sql, NULL, 0, &zErrMsg);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
            sqlite3_close(db);
            return 1;
        }
    }
    rc = sqlite3_prepare_v2(db, save ? insert_sql : get_file_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    if (check)
    {
        rc = sqlite3_prepare_v2(db, find_deleted_sql, -1, &deleted_stmt, NULL);
        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return 1;
        }
    }
    scan_dir(start_path, name, 0);
    sdsfree(start_path);
    sdsfree(name);
    sqlite3_close(db);
    return 0;
}
