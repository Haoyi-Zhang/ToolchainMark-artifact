#include <stdio.h>
#include <string.h>
int main(int n,char **v){if(n!=2)return 2;char x[64]={0};snprintf(x,sizeof(x),"%s",v[1]);printf("host:%zu\n",strlen(x));return 0;}
