#pragma once

#include <windows.h>
#include <stdio.h>
#include <iostream>

char* deobfuscate(unsigned char *s) {
	unsigned char key, mod, len;
	int i, j;
	static char d[256];

	key = s[0];
	mod = s[1];
	len = s[2] ^ key ^ mod;

	memset(d, 0x00, len + 1);

	for (i = 0, j = 3; i < len; i++, j++) {
		d[i] = s[j] ^ mod;
		d[i] -= mod;
		d[i] ^= key;
	}

	d[len] = 0;
	return d;
}