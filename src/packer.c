

#include "woody.h"


static size_t align_up(size_t value, size_t alignment)
{
    return (value + (alignment - 1)) & ~(alignment - 1); 
}


static bool fill_random_bytes(uint8_t *dst, size_t len)
{
    int     fd;
    size_t  filled;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("open /dev/urandom");
        return false;
    }
    filled = 0;
    while (filled < len)
    {
        ssize_t nread;

        nread = read(fd, dst + filled, len - filled);
        if (nread < 0)
        {
            perror("read /dev/urandom");
            close(fd);
            return false;
        }
        if (nread == 0)
        {
            fprintf(stderr, "Error: /dev/urandom returned EOF unexpectedly.\n");
            close(fd);
            return false;
        }
        filled += (size_t)nread;
    }
    if (close(fd) < 0)
    {
        perror("close /dev/urandom");
        return false;
    }
    return true;
}


static void xor_cipher(uint8_t *buf, size_t len, const uint8_t *key, size_t key_len)
{
    size_t i;

    for (i = 0; i < len; ++i)
        buf[i] ^= key[i % key_len];
}


static void encode_key_hex(const uint8_t *key, size_t len, char *out)
{
    static const char hexdigits[] = "0123456789ABCDEF";
    size_t            i;

    for (i = 0; i < len; ++i)
    {
        out[i * 2] = hexdigits[(key[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexdigits[key[i] & 0xF];
    }
    out[len * 2] = '\0';
}


static bool map_input_file(t_woody *ctx, const char *path)
{
    struct stat sb; 

    ctx->path = path; 
    ctx->fd = open(path, O_RDONLY); 
    if (ctx->fd < 0) 
    {
        perror("open"); 
        return false; 
    }
    if (fstat(ctx->fd, &sb) < 0) 
    {
        perror("fstat"); 
        return false; 
    }
    if (sb.st_size == 0) 
    {
        fprintf(stderr, "Error: input file '%s' is empty.\n", path); 
        return false; 
    }
    ctx->size = (size_t)sb.st_size; 

    ctx->map = mmap(NULL, ctx->size, PROT_READ, MAP_PRIVATE, ctx->fd, 0); 
    if (ctx->map == MAP_FAILED) 
    {
        ctx->map = NULL; 
        perror("mmap"); 
        return false; 
    }
    return true; 
}


static void unmap_input_file(t_woody *ctx)
{
    if (ctx->map != NULL) 
    {
        munmap(ctx->map, ctx->size); 
        ctx->map = NULL; 
    }
    if (ctx->fd >= 0) 
    {
        close(ctx->fd); 
        ctx->fd = -1; 
    }
}


static bool validate_elf64(const t_woody *ctx)
{
    const Elf64_Ehdr *hdr; 

    if (ctx->size < sizeof(Elf64_Ehdr)) 
    {
        fprintf(stderr, "Error: file '%s' is too small to be an ELF64 binary.\n",
                ctx->path); 
        return false; 
    }

    hdr = (const Elf64_Ehdr *)ctx->map; 

    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) 
    {
        fprintf(stderr, "Error: file '%s' does not start with ELF magic bytes.\n",
                ctx->path); 
        return false; 
    }
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) 
    {
        fprintf(stderr, "Error: file '%s' is not a 64-bit ELF (class=%u).\n",
                ctx->path, hdr->e_ident[EI_CLASS]); 
        return false; 
    }
    if (hdr->e_ident[EI_DATA] != ELFDATA2LSB) 
    {
        fprintf(stderr, "Error: file '%s' is not little-endian (data=%u).\n",
                ctx->path, hdr->e_ident[EI_DATA]); 
        return false; 
    }
    if (hdr->e_machine != EM_X86_64) 
    {
        fprintf(stderr,
                "Error: file '%s' targets architecture %u (expected x86_64).\n",
                ctx->path, hdr->e_machine); 
        return false; 
    }
    
    if (hdr->e_type != ET_EXEC && hdr->e_type != ET_DYN) 
    {
        fprintf(stderr,
                "Error: file '%s' has unsupported ELF type %u.\n",
                ctx->path, hdr->e_type); 
        return false; 
    }

    
    return true; 
}


static bool parse_program_headers(t_woody *ctx)
{
    const uint8_t   *base;              
    size_t           table_bytes;       
    size_t           i;                 
    bool             found_entry;       

    ctx->ehdr = (const Elf64_Ehdr *)ctx->map; 
    ctx->entry_point = ctx->ehdr->e_entry;    

    if (ctx->ehdr->e_phnum == 0) 
    {
        fprintf(stderr, "Error: file '%s' exposes no program headers.\n", ctx->path); 
        return false; 
    }

    if (ctx->ehdr->e_phoff > ctx->size) 
    {
        fprintf(stderr, "Error: file '%s' has program headers past EOF (offset=%llu, size=%zu).\n",
                ctx->path, (unsigned long long)ctx->ehdr->e_phoff, ctx->size); 
        return false; 
    }

    table_bytes = (size_t)ctx->ehdr->e_phnum * sizeof(Elf64_Phdr); 
    if (table_bytes > ctx->size - ctx->ehdr->e_phoff) 
    {
        fprintf(stderr, "Error: file '%s' has truncated program headers (need=%zu, available=%zu).\n",
                ctx->path, table_bytes, ctx->size - ctx->ehdr->e_phoff); 
        return false; 
    }

    base = ctx->map; 
    ctx->phdr_table = (const Elf64_Phdr *)(base + ctx->ehdr->e_phoff); 
    ctx->phdr_count = ctx->ehdr->e_phnum; 
    ctx->entry_segment = NULL; 
    ctx->entry_segment_index = 0; 

    found_entry = false; 
    for (i = 0; i < ctx->phdr_count; ++i) 
    {
        const Elf64_Phdr *candidate; 
        Elf64_Addr        seg_start; 
        Elf64_Addr        seg_end;   

        candidate = &ctx->phdr_table[i]; 
        if (candidate->p_type != PT_LOAD) 
            continue; 

        seg_start = candidate->p_vaddr; 
        seg_end = seg_start + candidate->p_memsz; 

        if (ctx->entry_point >= seg_start && ctx->entry_point < seg_end) 
        {
            ctx->entry_segment = candidate; 
            ctx->entry_segment_index = i; 
            found_entry = true; 
            break; 
        }
    }

    if (!found_entry) 
    {
        fprintf(stderr, "Error: file '%s' has entry point 0x%llx outside loadable segments.\n",
                ctx->path, (unsigned long long)ctx->entry_point); 
        return false; 
    }

    return true; 
}


static bool analyze_load_segments(t_woody *ctx)
{
    size_t i; 

    ctx->text_segment = NULL; 
    ctx->text_segment_index = 0; 
    ctx->payload_slack = 0; 
    ctx->payload_file_offset = 0; 
    ctx->payload_mem_addr = 0; 

    for (i = 0; i < ctx->phdr_count; ++i) 
    {
        const Elf64_Phdr *candidate; 

        candidate = &ctx->phdr_table[i]; 
        if (candidate->p_type != PT_LOAD) 
            continue; 
        if ((candidate->p_flags & PF_X) == 0) 
            continue; 

        ctx->text_segment = candidate; 
        ctx->text_segment_index = i; 
        ctx->text_file_offset = candidate->p_offset; 
        ctx->text_mem_addr = candidate->p_vaddr; 
        ctx->text_filesz = candidate->p_filesz; 
        ctx->text_memsz = candidate->p_memsz; 
        ctx->enc_region_start = candidate->p_vaddr; 
        ctx->enc_region_size = candidate->p_filesz; 

        ctx->payload_file_offset = ctx->text_file_offset + ctx->text_filesz; 
        ctx->payload_mem_addr = ctx->text_mem_addr + ctx->text_memsz; 

        if (candidate->p_memsz < candidate->p_filesz) 
        {
            fprintf(stderr,
                    "Error: executable segment #%zu has memsz smaller than filesz (mem=%llu, file=%llu).\n",
                    i,
                    (unsigned long long)candidate->p_memsz,
                    (unsigned long long)candidate->p_filesz); 
            return false; 
        }

        ctx->payload_slack = align_up(ctx->text_filesz, WOODY_PAGE_SIZE) - ctx->text_filesz; 
        return true; 
    }

    fprintf(stderr, "Error: file '%s' exposes no executable PT_LOAD segment (PF_X).\n",
            ctx->path); 
    return false; 
}


static bool prepare_loader_stub(t_woody *ctx)
{
    uint8_t *stub; 

    ctx->stub_size = g_woody_stub_size; 
    
    ctx->metadata_offset = ctx->stub_size - sizeof(t_woody_metadata); 
    if (ctx->payload_slack < ctx->stub_size) 
    {
        fprintf(stderr,
                "Error: executable segment #%zu offers only %zu bytes of slack (need %zu for stub).\n",
                ctx->text_segment_index,
                ctx->payload_slack,
                ctx->stub_size); 
        return false; 
    }

    stub = malloc(ctx->stub_size); 
    if (stub == NULL)
    {
        perror("malloc"); 
        return false; 
    }
    memcpy(stub, g_woody_stub, ctx->stub_size); 

    ctx->stub_image = stub; 
    ctx->stub_file_offset = ctx->payload_file_offset; 
    ctx->stub_entry = ctx->text_mem_addr + (ctx->stub_file_offset - ctx->text_file_offset); 

    return true; 
}


static bool plan_encryption(t_woody *ctx)
{
    ctx->metadata = (t_woody_metadata){
        .original_entry = ctx->entry_point,
        .enc_region_start = ctx->enc_region_start,
        .enc_region_size = (uint64_t)ctx->enc_region_size,
        .metadata_vaddr = ctx->stub_entry + ctx->metadata_offset,
    };

    if (!fill_random_bytes(ctx->metadata.key, WOODY_KEY_SIZE))
        return false;

    return true;
}


static bool emit_packed_binary(t_woody *ctx)
{
    size_t       required_size; 
    size_t       output_size;   
    uint8_t     *output;        
    Elf64_Ehdr  *ehdr;          
    Elf64_Phdr  *phdr_table;    
    Elf64_Phdr  *text_phdr;     
    int          fd;            
    ssize_t      written;       

    required_size = ctx->stub_file_offset + ctx->stub_size; 
    output_size = ctx->size; 
    if (output_size < required_size) 
        output_size = required_size;

    output = malloc(output_size); 
    if (output == NULL)
    {
        perror("malloc"); 
        return false;
    }
    memcpy(output, ctx->map, ctx->size); 
    if (output_size > ctx->size) 
        memset(output + ctx->size, 0, output_size - ctx->size);

    ehdr = (Elf64_Ehdr *)output; 
    phdr_table = (Elf64_Phdr *)(output + ctx->ehdr->e_phoff); 
    text_phdr = &phdr_table[ctx->text_segment_index]; 

    ehdr->e_entry = ctx->stub_entry; 
    text_phdr->p_filesz += ctx->stub_size; 
    text_phdr->p_memsz += ctx->stub_size;  

    xor_cipher(output + ctx->text_file_offset, ctx->enc_region_size,
               ctx->metadata.key, WOODY_KEY_SIZE); 

    memcpy(ctx->stub_image + ctx->metadata_offset, &ctx->metadata,
           sizeof(t_woody_metadata)); 
    memcpy(output + ctx->stub_file_offset, ctx->stub_image, ctx->stub_size); 

    fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755); 
    if (fd < 0)
    {
        perror("open"); 
        free(output);
        return false;
    }
    written = write(fd, output, output_size); 
    if (written < 0 || (size_t)written != output_size)
    {
        perror("write"); 
        close(fd);
        free(output);
        return false;
    }
    if (close(fd) < 0) 
    {
        perror("close");
        free(output);
        return false;
    }

    ctx->text_filesz = text_phdr->p_filesz; 
    ctx->text_memsz = text_phdr->p_memsz;

    free(output); 
    return true;
}

int run_packer(const char *input_path)
{
    t_woody ctx; 
    bool    ok; 

    
    ctx = (t_woody){ 
        .path = input_path, 
        .fd = -1, 
        .size = 0, 
        .map = NULL, 
        .ehdr = NULL, 
        .phdr_table = NULL, 
        .phdr_count = 0, 
        .entry_segment = NULL, 
        .entry_segment_index = 0, 
        .entry_point = 0, 
        .text_segment = NULL, 
        .text_segment_index = 0, 
        .text_file_offset = 0, 
        .text_mem_addr = 0, 
        .text_filesz = 0, 
        .text_memsz = 0, 
        .payload_slack = 0, 
        .payload_file_offset = 0, 
        .payload_mem_addr = 0, 
        .stub_image = NULL, 
        .stub_size = 0, 
        .stub_entry = 0, 
        .stub_file_offset = 0, 
        .enc_region_start = 0, 
        .enc_region_size = 0, 
        .metadata_offset = 0, 
        .metadata = {0}, 
    };

    if (!map_input_file(&ctx, input_path)) 
    {
        unmap_input_file(&ctx); 
        return -1; 
    }

    ok = validate_elf64(&ctx); 
    if (!ok) 
    {
        unmap_input_file(&ctx); 
        return -1; 
    }

    ok = parse_program_headers(&ctx); 
    if (!ok) 
    {
        unmap_input_file(&ctx); 
        return -1; 
    }

    ok = analyze_load_segments(&ctx); 
    if (!ok) 
    {
        unmap_input_file(&ctx); 
        return -1; 
    }

    ok = prepare_loader_stub(&ctx); 
    if (!ok) 
    {
        free(ctx.stub_image); 
        unmap_input_file(&ctx); 
        return -1; 
    }

    ok = plan_encryption(&ctx); 
    if (!ok)
    {
        free(ctx.stub_image);
        unmap_input_file(&ctx);
        return -1;
    }

    ok = emit_packed_binary(&ctx); 
    if (!ok)
    {
        free(ctx.stub_image);
        unmap_input_file(&ctx);
        return -1;
    }

    
    printf("Input '%s' validated as 64-bit x86_64 ELF (%zu bytes).\n",
           input_path, ctx.size); 
    printf("Entry point 0x%llx resides in loadable segment #%zu (file offset 0x%llx, filesz=%llu, memsz=%llu).\n",
           (unsigned long long)ctx.entry_point, ctx.entry_segment_index,
           (unsigned long long)ctx.entry_segment->p_offset,
           (unsigned long long)ctx.entry_segment->p_filesz,
           (unsigned long long)ctx.entry_segment->p_memsz); 
    printf("Executable segment #%zu mapped at file offset 0x%llx (mem 0x%llx) with filesz=%zu, memsz=%zu, slack=%zu bytes before alignment.\n",
           ctx.text_segment_index,
           (unsigned long long)ctx.text_file_offset,
           (unsigned long long)ctx.text_mem_addr,
           ctx.text_filesz,
           ctx.text_memsz,
           ctx.payload_slack); 
    printf("Prepared stub of %zu bytes; new entry will be 0x%llx (file offset 0x%llx).\n",
           ctx.stub_size,
           (unsigned long long)ctx.stub_entry,
           (unsigned long long)ctx.stub_file_offset); 
    {
        char key_hex[WOODY_KEY_SIZE * 2 + 1];

        encode_key_hex(ctx.metadata.key, WOODY_KEY_SIZE, key_hex); 
        printf("key_value: %s\n", key_hex);
    }
    printf("Wrote packed binary to './woody'.\n");

    free(ctx.stub_image); 
    unmap_input_file(&ctx); 
    return 0; 
}


