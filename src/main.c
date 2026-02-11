

#include "woody.h"


static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <64-bit ELF binary>\n"
            "\n"
            "woody_woodpacker will encrypt the provided binary and produce a\n"
            "new executable named 'woody'.\n",
            prog); 
}

int main(int argc, char **argv)
{
    int exit_code; 

    
    if (argc != 2) 
    {
        print_usage(argv[0]); 
        return EXIT_FAILURE; 
    }

    
    exit_code = run_packer(argv[1]); 
    if (exit_code != 0) 
    {
        
        return EXIT_FAILURE; 
    }

    return EXIT_SUCCESS; 
}

