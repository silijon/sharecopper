#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <libsmbclient.h>
#include "dbg.h"
#include "jproc.h"

#define NUM_PROCS 2
#define BLOCK_SIZE 65536
#define PERMS 0644

int debuglevel = 0;
const char *workgroup = "WORKGROUP";
const char *username = "guest";
const char *password = "";

typedef struct blockdef_t {
    const char *src_file_name;
    const char *tgt_file_name;
    size_t block_size;
    off_t offset;
    int num_blocks;
} blockdef_t;

static void smbc_auth_fn(
        const char      *server,
        const char      *share,
        char            *wrkgrp, int wrkgrplen,
        char            *user,   int userlen,
        char            *passwd, int passwdlen)
{

    (void) server;
    (void) share;
    (void) wrkgrp;
    (void) wrkgrplen;

    strncpy(wrkgrp, workgroup, wrkgrplen - 1); wrkgrp[wrkgrplen - 1] = 0;
    strncpy(user, username, userlen - 1); user[userlen - 1] = 0;
    strncpy(passwd, password, passwdlen - 1); passwd[passwdlen - 1] = 0;
}

static SMBCCTX* create_smbctx(void) 
{
    SMBCCTX *ctx;

    ctx = smbc_new_context();
    check(ctx, "Failed to create new context");

    smbc_setDebug(ctx, debuglevel);
    smbc_setFunctionAuthData(ctx, smbc_auth_fn);

    check(smbc_init_context(ctx), "Failed to init new context");
    return ctx;

error:
    if (ctx) smbc_free_context(ctx, 1);
    return NULL;
}

static void destroy_smbctx(SMBCCTX* ctx) 
{
    smbc_getFunctionPurgeCachedServers(ctx)(ctx);
    smbc_free_context(ctx, 1);
}

static off_t get_smbfilesize(const char *file_name)
{
    // create smb context
    SMBCCTX *ctx = create_smbctx();
    checkp(ctx, "create_smbctx");
    debug("Created SMB context");

    // stat the file
    struct stat file_stat;
    int ret = smbc_getFunctionStat(ctx)(ctx, file_name, &file_stat);
    checkp(ret == 0, "smbc_stat");

    destroy_smbctx(ctx);
    return file_stat.st_size;

error:
    if (ctx) destroy_smbctx(ctx);
    return -1;
}

void *copy_block(void *blockdef_ptr)
{
    SMBCFILE *src_file = NULL;
    int tgt_fd = -1;
    blockdef_t *block = (blockdef_t*)blockdef_ptr;
    unsigned char buf[block->block_size];

    debug("Copying %d blocks at offset: %jd", block->num_blocks, (intmax_t)block->offset);

    // create SMB context
    SMBCCTX *ctx = create_smbctx();
    checkp(ctx, "create_smbctx");
    debug("Created SMB context");
    
    // open source
    src_file = smbc_getFunctionOpen(ctx)(ctx, block->src_file_name, O_RDONLY, 0);
    checkp(src_file, "smbc_getFunctionOpen");
    debug("Opened source file: %s", block->src_file_name);

    // seek to offset
    int ret = smbc_getFunctionLseek(ctx)(ctx, src_file, block->offset, SEEK_SET);
    checkp(ret > -1, "smbc_getFunctionLseek");

    // open target
    tgt_fd = open(block->tgt_file_name, O_WRONLY | O_CREAT, PERMS);
    checkp(tgt_fd > -1, "open");
    debug("Opened target file: %s", block->tgt_file_name);
    
    // copy
    ssize_t red, writ;
    off_t write_offset = block->offset;
    int i;
    for (i = 0; i < block->num_blocks; i++) {
        red = smbc_getFunctionRead(ctx)(ctx, src_file, buf, block->block_size);
        checkp(red > -1, "smbc_read");

        if (red == 0)
            break;

        if (red > 0) { 
          writ = pwrite(tgt_fd, buf, red, write_offset);
          checkp(writ > -1, "write");
          write_offset += writ;
        }
    } 

    smbc_getFunctionClose(ctx)(ctx, src_file);
    destroy_smbctx(ctx);
    close(tgt_fd);

    return NULL;

error:
    if (src_file) smbc_getFunctionClose(ctx)(ctx, src_file);
    if (ctx) destroy_smbctx(ctx);
    if (tgt_fd > -1) close(tgt_fd);
    return NULL;
}


int main(int argc, char *argv[])
{
    check(argc == 3, "Usage: sharecopper [source] [target]");

    // stat source file to get size
    off_t src_file_size = get_smbfilesize(argv[1]);
    check(src_file_size > -1, "get_smbcfilesize");
    debug("Source file size: %jd", (intmax_t)src_file_size);

    int num_blocks = src_file_size/BLOCK_SIZE;
    if (src_file_size % BLOCK_SIZE > 0)
        num_blocks++;
    debug("Num blocks: %d", num_blocks);

    int num_blocks_per_proc = num_blocks / NUM_PROCS;
    debug("Num blocks per process: %d", num_blocks_per_proc);

    int num_leftover_blocks = num_blocks % NUM_PROCS; 
    debug("Num leftover blocks: %d", num_leftover_blocks);

    // create procs
    off_t segment_offset = 0;
    jproc_t procs[NUM_PROCS];

    int i;
    for (i = 0; i < NUM_PROCS; i++) {
        if (segment_offset > src_file_size)
            break;

        blockdef_t block = { 
            .src_file_name = argv[1],
            .tgt_file_name = argv[2],
            .block_size = BLOCK_SIZE,
            .offset = segment_offset,
            .num_blocks = num_blocks_per_proc
        };

        // if there are remainder blocks, assign them to the first process
        if (i == 0)
            block.num_blocks += num_leftover_blocks;

        debug("Creating proc: %d", i);
        jproc_create(&procs[i], copy_block, (void *)&block); 

        // track the offset
        segment_offset += (block.block_size * block.num_blocks);
        debug("Current segment offset: %jd", (intmax_t)segment_offset);
    }

    // join procs
    int j;
    for (j = 0; j < i; j++) {
        debug("Joining proc: %d", j);
        debug("Proc complete: %d", jproc_join(procs[j], NULL));
    }

    debug("Success.");
    exit(EXIT_SUCCESS);

error:
    debug("Fail.");
    exit(EXIT_FAILURE);
}
