//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
#include "main.h"

void gen_random(char *s, const int len) { //ripped & modified "added srand()" from http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int TextChecksum8(char* text)
{
	UINT temp = 0;
	for(UINT i = 0; i < strlen(text); i++)
	{
		temp += (int)text[i];
	}
	return temp % 0x100;
}