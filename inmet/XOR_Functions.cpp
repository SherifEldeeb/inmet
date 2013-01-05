//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
#include "main.h"

void XORcrypt(unsigned char *buffer, char *key, int size)
{
	int key_length = strlen(key);

	int i = 0 ;
	int position = 0;

	for(i = 0; i < size; i++)
	{
		position = i % key_length;
		buffer[i] ^=  key[position];
	}
}

void GetKeyFromBuffer(unsigned char* buffer, char* key, int size) //useless since we can memcpy and that's it, I know, but I  made this for myself to get things less confusing
{
	int i = 0 ;

	for(i = 0; i < size; i++)
	{
		key[i] =  buffer[i];
	}
	key[size] = '\0';
}