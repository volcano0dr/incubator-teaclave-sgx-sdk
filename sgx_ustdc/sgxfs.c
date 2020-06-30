// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <errno.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define O_LARGEFILE 0100000

inline void set_error(int32_t *error, int32_t code) {
    if (error != NULL) {
        *error = code;
    }
}

void *u_sgxfs_open_ocall(int32_t *error, const char *filename, uint8_t read_only, int64_t *file_size)
{
    FILE *file = NULL;
    int result = 0;
    int fd = -1;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    struct stat stat_st;

    memset(&stat_st, 0, sizeof(struct stat));

    if (filename == NULL || strnlen(filename, 1) == 0)
    {
        set_error(error, EINVAL);
        return NULL;
    }

    // open the file with OS API so we can 'lock' the file and get exclusive access to it
    fd = open(filename,	O_CREAT | (read_only ? O_RDONLY : O_RDWR) | O_LARGEFILE, mode); // create the file if it doesn't exists, read-only/read-write
    if (fd == -1)
    {
        set_error(error, errno);
        return NULL;
    }

    // this lock is advisory only and programs with high priviliges can ignore it
    // it is set to help the user avoid mistakes, but it won't prevent intensional DOS attack from priviliged user
    result = flock(fd, (read_only ? LOCK_SH : LOCK_EX) | LOCK_NB); // NB - non blocking
    if (result != 0)
    {
        set_error(error, errno);
        result = close(fd);
        assert(result == 0);
        return NULL;
    }

    result = fstat(fd, &stat_st);
    if (result != 0)
    {
        set_error(error, errno);
        flock(fd, LOCK_UN);
        result = close(fd);
        assert(result == 0);
        return NULL;
    }
    
    // convert the file handle to standard 'C' API file pointer
    file = fdopen(fd, read_only ? "rb" : "r+b");
    if (file == NULL)
    {
        set_error(error, errno);
        flock(fd, LOCK_UN);
        result = close(fd);
        assert(result == 0);
        return NULL;
    }

    if (file_size != NULL)
        *file_size = stat_st.st_size;

    return (void *)file;
}


uint8_t u_sgxfs_read_ocall(int32_t *error, void *f, uint64_t node_number, uint8_t *node, uint32_t node_size)
{
    FILE *file = (FILE *)f;
    uint64_t offset = node_number * node_size;
    size_t size = 0;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }

    if (fseeko(file, (off_t)offset, SEEK_SET) != 0)
    {
        set_error(error, errno);
        return 0;
    }

    if ((size = fread(node, node_size, 1, file)) != 1)
    {
        int err = ferror(file);
        if (err != 0) {
            set_error(error, err);
        } else {
            set_error(error, errno);
        }
        return 0;
    }

    return 1;
}


uint8_t u_sgxfs_write_ocall(int32_t *error, void *f, uint64_t node_number, uint8_t *node, uint32_t node_size)
{
    FILE *file = (FILE *)f;
    uint64_t offset = node_number * node_size;
    size_t size = 0;
    int err = 0;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }

    if (fseeko(file, (off_t)offset, SEEK_SET) != 0)
    {
        set_error(error, errno);
        return 0;
    }

    if ((size = fwrite(node, node_size, 1, file)) != 1)
    {
        err = ferror(file);
        if (err != 0) {
            set_error(error, err);
        } else {
            set_error(error, errno);
        }
        return 0;
    }

    return 1;
}

uint8_t u_sgxfs_close_ocall(int32_t *error, void *f)
{
    FILE *file = (FILE *)f;
    int fd = 0;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }

    // closing the file handle should also remove the lock, but we try to remove it explicitly
    fd = fileno(file);
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    
    if (fclose(file) != 0)
    {
        set_error(error, errno);
        return 0;
    }

    return 1;
}

uint8_t u_sgxfs_flush_ocall(int32_t *error, void *f)
{
    FILE *file = (FILE *)f;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }
    
    if (fflush(file) != 0)
    {
        set_error(error, errno);
        return 0;
    }
    
    return 1;
}

#define MILISECONDS_SLEEP_FOPEN 10
#define MAX_FOPEN_RETRIES       10
void *u_sgxfs_open_recovery_ocall(int32_t *error, const char *filename)
{
    FILE *file = NULL;
    int32_t err = 0;
    int i = 0;

    if (filename == NULL || strnlen(filename, 1) == 0)
    {
        set_error(error, EINVAL);
        return NULL;
    }
    
    for (i = 0; i < MAX_FOPEN_RETRIES; i++)
    {
        file = fopen(filename, "wb");
        if (file != NULL) {
            break;
        } else {
            err = errno;
        }
        usleep(MILISECONDS_SLEEP_FOPEN);
    }
    if (file == NULL)
    {
        set_error(error, err);
        return NULL;
    }
    
    return file;
}

uint8_t u_sgxfs_write_recovery_ocall(int32_t *error, void *f, uint8_t *data, uint32_t data_size)
{
    FILE *file = (FILE*)f;
    size_t count = 0;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }
        
    // recovery nodes are written sequentially
    count = fwrite(data, 1, data_size, file);
    if (count != data_size)
    {
        set_error(error, errno);
        return 0;
    }

    return 1;
}

uint8_t u_sgxfs_close_recovery_ocall(int32_t *error, void *f)
{
    FILE *file = (FILE *)f;

    if (file == NULL)
    {
        set_error(error, EINVAL);
        return 0;
    }
    
    if (fclose(file) != 0)
    {
        set_error(error, errno);
        return 0;
    }

    return 1;
}

uint8_t u_sgxfs_exists_ocall(int32_t *error, const char *filename)
{
    struct stat stat_st;
    
    memset(&stat_st, 0, sizeof(struct stat));

    if (filename == NULL || strnlen(filename, 1) == 0)
    {
        set_error(error, EINVAL);
        return 0;
    }
    
    if (stat(filename, &stat_st) != 0) {
        return 0;
    }

    return 1;
}


uint8_t u_sgxfs_remove_ocall(int32_t *error, const char *filename)
{
    if (filename == NULL || strnlen(filename, 1) == 0)
    {
        set_error(error, EINVAL);
        return 0;
    }

    if (remove(filename) != 0)
    {
        set_error(error, errno);
        return 0;
    }
    
    return 1;
}

#define NODE_SIZE  4096
#define RECOVERY_NODE_SIZE  (sizeof(uint64_t) + NODE_SIZE)

uint8_t u_sgxfs_recovery_ocall(int32_t *error, const char *filename, const char *recovery_filename)
{
    FILE *recovery_file = NULL;
    FILE *source_file = NULL;
    uint8_t ret = 0;
    int32_t err = 0;
    uint32_t nodes_count = 0;
    uint32_t i = 0;
    uint64_t file_size = 0;
    size_t count = 0;
    uint8_t *recovery_node = NULL;

    do 
    {
        if (filename == NULL || strnlen(filename, 1) == 0)
        {
            set_error(error, EINVAL);
            return 0;
        }

        if (recovery_filename == NULL || strnlen(recovery_filename, 1) == 0)
        {
            set_error(error, EINVAL);
            return 0;
        }
    
        recovery_file = fopen(recovery_filename, "rb");
        if (recovery_file == NULL)
        {
            set_error(error, errno);
            break;
        }

        if (fseeko(recovery_file, 0, SEEK_END) != 0)
        {
            set_error(error, errno);
            break;
        }

        file_size = (uint64_t)ftello(recovery_file);
    
        if (fseeko(recovery_file, 0, SEEK_SET) != 0)
        {
            set_error(error, errno);
            break;
        }

        if (file_size % RECOVERY_NODE_SIZE != 0)
        {
            set_error(error, ENOTSUP);
            break;
        }

        nodes_count = (uint32_t)(file_size / RECOVERY_NODE_SIZE);

        recovery_node = (uint8_t*)malloc(RECOVERY_NODE_SIZE);
        if (recovery_node == NULL)
        {
            set_error(error, ENOMEM);
            break;
        }

        source_file = fopen(filename, "r+b");
        if (source_file == NULL)
        {
            set_error(error, errno);
            break;
        }

        for (i = 0 ; i < nodes_count ; i++)
        {
            if ((count = fread(recovery_node, RECOVERY_NODE_SIZE, 1, recovery_file)) != 1)
            {
                err = ferror(recovery_file);
                if (err != 0) {
                    set_error(error, err);
                } else {
                    set_error(error, errno);
                }
                break;
            }

            // seek the regular file to the required offset
            if (fseeko(source_file, (*((off_t*)recovery_node)) * NODE_SIZE, SEEK_SET) != 0)
            {
                set_error(error, errno);
                break;
            }

            // write down the original data from the recovery file
            if ((count = fwrite(&recovery_node[sizeof(uint64_t)], NODE_SIZE, 1, source_file)) != 1)
            {
                err = ferror(source_file);
                if (err != 0) {
                    set_error(error, err);
                } else {
                    set_error(error, errno);
                }
                break;
            }
        }

        if (i != nodes_count) // the 'for' loop exited with error
            break;

        if (fflush(source_file) != 0)
        {
            set_error(error, errno);
            break;
        }

        ret = 1;

    } while(0);

    if (recovery_node != NULL)
        free(recovery_node);

    if (source_file != NULL)
    {
        fclose(source_file);
    }

    if (recovery_file != NULL)
    {
        fclose(recovery_file);
    }

    if (ret == 1)
        remove(recovery_filename);
    
    return ret;
}
