// +build ignore
#include<stdio.h>
#include<linux/if_ether.h>

int main(int argc, char** argv){
    struct ethhdr *eth;
    unsigned int i=2;
    void *p = (void *)(long)i;
    printf("Size of long %ld\n", sizeof(long));
    printf("Size of int %ld\n", sizeof(int));
    printf("Size of uint %ld\n", sizeof(unsigned int));
    printf("Size of eth %ld\n", sizeof(*eth));
    printf("Size of str eth %ld\n", sizeof(struct ethhdr));
    printf("Size of uint %ld\n", sizeof((void *)(long)i));      
    printf("Size of vpoint %ld\n", sizeof(p));      
    printf("i=%u, &i=%p\n", i, &i);      
    printf("p=%p\n", (p));      
    return 0;
}