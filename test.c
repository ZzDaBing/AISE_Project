#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

int f3(int i)
{
	int j = 0x44444444;
	return i + j;
}

int f2(int i, int j)
{
	int k = f3(i + j);
	return k;
}

int f1(int i)
{
	return f2(i, 0x22222222);
}

int main(int argc, char const *argv[])
{
	char *p = "toto";
	printf("%s\n", p);
	//while(1);
	p[0] = 'l';
	printf("%s\n", p);

	int h = f1(0x11111111);
	printf("Hello ! f1 returned %X\n", h);
	
	return 0;
}
