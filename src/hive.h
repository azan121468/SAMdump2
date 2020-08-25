/*  Hive.h
	Hive file access, pretty lame and bugged but do the work O_o
	Thanks to B.D. for file structure info

	DISCLAIMER:
	This is  free  software, so you are free to copy, distribute, use
	the work under the following condition

	You must give the original author credit.
	You may not use this work for commercial purposes.

	I'm in NO WAY responsible for any damage the program does.
	This program is distributed in the hope that it will be useful, but
	WITHOUT  ANY  WARRANTY,  express  or  implied.  There is no implied
	warranty  of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE !
	Using it is at your own risk !

	Any of these conditions can be waived if you get permission from the author.

	Nicola Cuomo - ncuomo@studenti.unina.it
*/

#ifndef HIVE_H
#define HIVE_H

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

struct hive
{
	unsigned char *base;
};

typedef struct _nk_hdr 
{
	WORD	id;
	WORD	type;
	DWORD	t1, t2;
	DWORD	unk1;
	DWORD	parent_off;
	DWORD	subkey_num;
	DWORD	unk2;
	DWORD	lf_off;
	DWORD	unk3;
	DWORD	value_cnt;
	DWORD	value_off;
	DWORD	sk_off;
	DWORD	classname_off;
	DWORD	unk4[4];
	DWORD	unk5;
	WORD	name_len;
	WORD	classname_len;
	char	key_name[1]; 
} nk_hdr;

typedef struct _hashrecord 
{

	DWORD	nk_offset;
	char	keyname[4];
} hashrecord;

typedef struct _lf_hdr 
{
	WORD	id;
	WORD	key_num;
	hashrecord hr[1];
} lf_hdr;

#define NK_ID	0x6B6E
#define NK_ROOT 0x2c

#define LF_ID	0x666C

#define read_nk( hive, offset ) ( (nk_hdr*) (hive->base + offset + 4)  )
#define read_lf( hive, offset ) ( (lf_hdr*) (hive->base + offset + 4)  )
#define read_vk( hive, offset ) ( (vk_hdr*) (hive->base + offset + 4)  )
#define read_valuelist( hive, offset ) ( (DWORD*) (hive->base + offset + 4)  )
#define read_data( hive, offset ) ( (unsigned char*) ((hive)->base + offset + 4)  )

typedef struct _vk_hdr 
{
	WORD  id;
	WORD  name_len;
	DWORD data_len;
	DWORD data_off;
	DWORD data_type;
	WORD  flag;
	WORD unk1;
	char value_name[1];
} vk_hdr;

void _RegCloseHive( struct hive *h );

void _InitHive( struct hive *h );

int _RegOpenHive( char *filename, struct hive *h );

unsigned long parself( struct hive *h, char *t, unsigned long off );

int _RegOpenKey( struct hive *h, char *path, nk_hdr **nr );

int _RegQueryValue( struct hive *h, char *name, nk_hdr *nr, unsigned char **buff, int *len );

int _RegEnumKey( struct hive *h, nk_hdr *nr, unsigned int index, char *name, int *namelen );

#endif
