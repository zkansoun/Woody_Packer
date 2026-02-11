#ifndef WOODY_H
#define WOODY_H



#include <errno.h>      
#include <fcntl.h>      
#include <stdbool.h>    
#include <stddef.h>     
#include <stdint.h>     
#include <stdio.h>      
#include <stdlib.h>     
#include <string.h>     
#include <sys/mman.h>   
#include <sys/stat.h>   
#include <sys/types.h>  
#include <unistd.h>     
#include <elf.h>        


#define WOODY_PAGE_SIZE 0x1000u
#define WOODY_KEY_SIZE  32u

typedef struct s_woody_metadata
{
    Elf64_Addr original_entry;   
    Elf64_Addr enc_region_start; 
    uint64_t   enc_region_size;  
    Elf64_Addr metadata_vaddr;   
    uint8_t    key[WOODY_KEY_SIZE]; 
}   t_woody_metadata;


typedef struct s_woody
{
    const char     *path;                
    int             fd;                  
    size_t          size;                
    uint8_t        *map;                 
    const Elf64_Ehdr *ehdr;              
    const Elf64_Phdr *phdr_table;        
    Elf64_Half      phdr_count;          
    const Elf64_Phdr *entry_segment;     
    size_t          entry_segment_index; 
    Elf64_Addr      entry_point;         
    const Elf64_Phdr *text_segment;      
    size_t          text_segment_index;  
    Elf64_Off       text_file_offset;    
    Elf64_Addr      text_mem_addr;       
    size_t          text_filesz;         
    size_t          text_memsz;          
    size_t          payload_slack;       
    Elf64_Off       payload_file_offset; 
    Elf64_Addr      payload_mem_addr;    
    uint8_t        *stub_image;          
    size_t          stub_size;           
    Elf64_Addr      stub_entry;          
    Elf64_Off       stub_file_offset;    
    Elf64_Addr      enc_region_start;    
    size_t          enc_region_size;     
    size_t          metadata_offset;     
    t_woody_metadata metadata;           
}   t_woody;


int run_packer(const char *input_path);


extern const uint8_t g_woody_stub[];
extern const size_t  g_woody_stub_size;

#endif 

