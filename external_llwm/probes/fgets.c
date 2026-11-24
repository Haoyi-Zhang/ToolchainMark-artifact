#include <stdio.h>
#include <string.h>
int main(void){char x[64]={0};if(!fgets(x,sizeof(x),stdin))return 0;printf("host:%zu\n",strlen(x));return 0;}
