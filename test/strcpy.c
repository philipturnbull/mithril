#include <string.h>

int copy(char *s) {
	char buf[128];
	strcpy(buf, s);
	return strlen(buf) + 1;
}
