/*  Hive.cpp 
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

#include "hive.h"

void _RegCloseHive( struct hive *h )
{
	if( h->base != NULL )
		free( h->base );

	return;
}

void _InitHive( struct hive *h )
{
	h->base = NULL;

	return;
}

int _RegOpenHive( char *filename, struct hive *h )
{
	FILE *hiveh;
	unsigned long hsize;

	/* Prova ad aprire l'hive */
	if( ( hiveh = fopen( filename, "rb" ) ) != NULL )
	{
		if( fseek( hiveh, 0, SEEK_END ) == 0 )
		{
			hsize = ftell( hiveh );

			/* Legge il file in memoria */
			/* MMF ??? -_- */
			h->base = (unsigned char *) malloc( hsize );

			fseek( hiveh, 0, SEEK_SET );

			if( fread( (void *) h->base, hsize, 1, hiveh ) == 1 )
				if( *((int*)h->base) == 0x66676572 )
				{
					fclose( hiveh );				
					return 0;
				}
		}

		fclose( hiveh );
	}

	return -1;
}

unsigned long parself( struct hive *h, char *t, unsigned long off )
{
	nk_hdr *n;
	lf_hdr *l;

	int i;

	l = read_lf( h, off );

	for( i = 0; i < l->key_num; i++ )
	{	
		n = read_nk( h, l->hr[i].nk_offset + 0x1000 );

		if( !memcmp( t, n->key_name, n->name_len ) )
			return l->hr[i].nk_offset;
	}

	return -1;
}

int _RegOpenKey( struct hive *h, char *path, nk_hdr **nr )
{
	nk_hdr *n;
	char *t, *tpath;
	unsigned long noff;

	n = read_nk( h, 0x1020 );

	if( n->id == NK_ID && n->type == NK_ROOT )
	{
		tpath = strdup( path );

		t = strtok( tpath, "\\" );

		if( !memcmp( t, n->key_name, n->name_len ) )
		{


			t = strtok( NULL, "\\" );

			while( t != NULL )
			{
				if( ( noff = parself( h, t, n->lf_off + 0x1000 ) ) == -1 )
					return -1;

				n = read_nk( h, noff + 0x1000 );

				t = strtok( NULL, "\\" );
			}

			*nr = n;

			return 0;
		}

		free( tpath );

	}

	return -1;
}

int _RegQueryValue( struct hive *h, char *name, nk_hdr *nr, unsigned char **buff, int *len )
{
	vk_hdr *v;
	unsigned int i;
	DWORD *l;

	l = read_valuelist( h, nr->value_off + 0x1000 );

	*buff = NULL;
	*len = 0;

	for( i = 0; i < nr->value_cnt; i++ )
	{
		v = read_vk( h, l[i] + 0x1000 );

		if( !strcmp( name, v->value_name ) || (name == NULL && ( v->flag & 1 ) == 0 ) )
		{
			*len =  v->data_len;

			*buff = ( v->data_len < 5 ) ?  (unsigned char* )(&v->data_off): read_data( h, v->data_off + 0x1000 );

			return 0;
		}
	}

	return -1;
}

int _RegEnumKey( struct hive *h, nk_hdr *nr, unsigned int index, char *name, int *namelen )
{
	lf_hdr *lf;
	nk_hdr *nk;

	if( index < nr->subkey_num )
	{
		lf = read_lf( h, nr->lf_off + 0x1000 );

		nk = read_nk( h, lf->hr[index].nk_offset + 0x1000 );

		memcpy( name, nk->key_name, min( *namelen, nk->name_len ) );

		name[ min( *namelen, nk->name_len ) ] = 0;
		*namelen = nk->name_len;

		return ( (index + 1) < nr->subkey_num ) ? (index + 1) : -1;
	}

	return -1;
}