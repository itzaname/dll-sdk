#include "api.h"

// Get length of string by finding the null terminator
// Due to its nature the string MUST have a null terminator
int strlen(const char* str)
{
	int index = 0;
	while (str[index] != '\0') // This can easily go bad
		index++;

	return index;
}

// Compare lengths then loops the length and compares
BOOL strcmp(const char* str1,const char* str2)
{
    // Calling strlen on str1 should probably be moved into a
    // variable as it can be expensive since optimization is
    // disabled and the loops wont be unrolled.
	if (strlen(str1) != strlen(str2))
		return 0;

	for (int i = 0; i < strlen(str1); ++i)
	{
		if (str1[i] != str2[i])
			return 0;
	}

	return 1;
}