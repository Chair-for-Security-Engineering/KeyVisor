#include <stdio.h>
#include <stdlib.h>
#include "../include/keyvisor/instructions.h"

int main(void)
{
    uint64_t result = 0;

    // load demo visor key for testing
    result = LOADCPUKEY(0xAFFEAFFEAFFEAFFE, 0xAFFEAFFEAFFEAFFE);

    if(result == 0){
        printf("Successfully loaded visor key.\n");
        return 0;
    }else if(result == 2){
        printf("Successfully loaded visor key. Old key was overwritten.\n");
        return 0;
    }else{
        printf("Load Visor Key FAILED - Got: %ld\n", result); 
        return 1;
    }
}
