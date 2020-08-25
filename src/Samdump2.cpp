/*  Samdump2
    Dump nt/lanman password hashes from a sam hive with Syskey enabled

    Thank to Dmitry Andrianov for the program name ^_^
    
    This product includes cryptographic software written by
    Eric Young (eay@cryptsoft.com)
    
    Thanks Eric ^_^

    DISCLAIMER:
    Samdump2 is  free  software, so you are free to copy, distribute, use
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

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "rc4.h"
#include "md5.h"
#include "hive.h"

typedef int (WINAPI *SF)(unsigned char*, int*, unsigned char*);

int main( int argc, char **argv )
{
    FILE *f;
    unsigned char bootkey[] = { 0x15, 0xbd, 0x18, 0x82, 0xfa, 0x6e, 0xf7, 0xe3, 0x87, 0x90, 0x67, 0x62, 0xd3, 0xfd, 0x5b, 0x03 };

    /* const */
    char regaccountkey[] = "SAM\\SAM\\Domains\\Account";
    char reguserskey[] = "SAM\\SAM\\Domains\\Account\\Users";
    unsigned char aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
    unsigned char anum[] = "0123456789012345678901234567890123456789";
    unsigned char antpassword[] = "NTPASSWORD";
    unsigned char almpassword[] = "LMPASSWORD";

    /* hive */
    struct hive h;
    nk_hdr *n = NULL;
    
    /* hive buffer */
    unsigned char *b;
    int blen;   
    unsigned char regkeyname[50];
    int regkeynamelen;
    char  *keyname;

    /* md5 contex, hash, rc4 key, hashed bootkey */
    MD5_CTX md5c;
    unsigned char md5hash[0x10];
    RC4_KEY rc4k;
    unsigned char hbootkey[0x20];

    int i, j;

    char *username;
    int rid;
    int usernameoffset, usernamelen;
    int hashesoffset;

    unsigned char obfkey[0x10];
    unsigned char fb[0x10];

    /* fun */
    HINSTANCE hinstLib;
    SF sf27; 
    SF sf25;
    
    fprintf( stderr, "Samdump2 ncuomo@studenti.unina.it\nThis product includes cryptographic software written\nby Eric Young (eay@cryptsoft.com)\n\n" );

    if( argc != 3 )
    {
        printf( "Usage:\nsamdump2 samhive keyfile\n" );
        return -1;
    }

    if( ( hinstLib = LoadLibrary( "ADVAPI32.DLL" ) ) != NULL ) 
    { 
        sf27 = (SF) GetProcAddress( hinstLib, "SystemFunction027" ); 
        sf25 = (SF) GetProcAddress( hinstLib, "SystemFunction025" ); 
    }
    else
        return -1;
    

    /* Open bootkey file */
    if( ( f = fopen( argv[2], "rb" ) ) != NULL )
    {
        fread( &bootkey, 1, 16, f );

        fclose( f );
    }
    else
    {
        fprintf( stderr, "Error reading from %s\n", argv[2] );
        return -1;
    }

    /* Initialize registry access function */
    _InitHive( &h );

    /* Open sam hive */
    if( _RegOpenHive( argv[1], &h ) )
    {
        fprintf( stderr, "Error opening sam hive or not valid file(\"%s\")\n", argv[1] );
        return -1;
    }

    /* Open SAM\\SAM\\Domains\\Account key*/
    if( _RegOpenKey( &h, regaccountkey, &n ) )
    {
        _RegCloseHive( &h );

        fprintf( stderr, "%s key!\n", regaccountkey );
        return -1;
    }
    
    if( _RegQueryValue( &h, "F", n, &b, &blen ) )
    {       
        _RegCloseHive( &h );

        fprintf( stderr, "No F!\n" );
        return -1;
    }

    /* hash the bootkey */
    MD5_Init( &md5c );
    MD5_Update( &md5c, &b[0x70], 0x10 );
    MD5_Update( &md5c, aqwerty, 0x2f );
    MD5_Update( &md5c, bootkey, 0x10 );
    MD5_Update( &md5c, anum, 0x29 );
    MD5_Final( md5hash, &md5c );
    RC4_set_key( &rc4k, 0x10, md5hash );
    RC4( &rc4k, 0x20, &b[0x80], hbootkey );

    j = 0;

    /* Enumerate user */
    while( j != -1 )
    {
        /* Open  SAM\\SAM\\Domains\\Account\\Users */
        if( _RegOpenKey( &h, reguserskey, &n ) )
        {
            _RegCloseHive( &h );

            fprintf( stderr, "No Users key!\n" );
            return -1;
        }

        regkeynamelen = sizeof( regkeyname );
        
        j = _RegEnumKey( &h, n, j, (char*)regkeyname, &regkeynamelen );
        
        /* Skip Names key */
        if( !memcmp( regkeyname, "Names", regkeynamelen ) )
            continue;

        keyname = (char*) malloc( strlen( reguserskey ) + regkeynamelen + 2 );
            
        /* Open SAM\\SAM\\Domains\\Account\\Users\\userrid */
        strcpy( keyname, reguserskey );
        strcat( keyname, "\\" ) ;
        strcat( keyname, (char*)regkeyname ) ;

        if( _RegOpenKey( &h, keyname, &n ) )
        {
            _RegCloseHive( &h );

            fprintf( stderr, "Asd -_- _RegEnumKey fail!\n" );
            return -1;
        }

        if( _RegQueryValue( &h, "V", n, &b, &blen ) )
        {
            _RegCloseHive( &h );

            fprintf( stderr, "No V value!\n" );
            return -1;
        }

        /* rid */
        rid = strtoul( (char*)regkeyname, NULL, 16 );

        /* get the username */
        /* 0x10 username size 0xc username offset */
        usernamelen = *(int*)(b + 0x10) >> 1;
        usernameoffset = b[0xc] + 0xcc;

        username = (char *) malloc(  usernamelen + 1 );
        wcstombs( username, (const wchar_t*)&b[usernameoffset], usernamelen );

        username[ usernamelen ] = 0;

        hashesoffset = *(int *)(b + 0x9c ) + 0xcc;

        if( hashesoffset + 0x28 < blen )
        {
            /* Print the user hash */
            printf( "%s:%d:", username, rid );

            /* LANMAN */
            /* hash the hbootkey and decode lanman password hashes */
            MD5_Init( &md5c );
            MD5_Update( &md5c, hbootkey, 0x10 );
            MD5_Update( &md5c, &rid, 0x4 );
            MD5_Update( &md5c, almpassword, 0xb );
            MD5_Final( md5hash, &md5c );        

            RC4_set_key( &rc4k, 0x10, md5hash );
            RC4( &rc4k, 0x10, &b[ hashesoffset + 4 ], obfkey );

            sf25( obfkey, (int*)&rid, fb );

            for( i = 0; i < 0x10; i++ )
                printf( "%.2x", fb[i] );

            printf( ":" );

            /* NT */
            /* hash the hbootkey and decode the nt password hashes */
            MD5_Init( &md5c );
            MD5_Update( &md5c, hbootkey, 0x10 );
            MD5_Update( &md5c, &rid, 0x4 );
            MD5_Update( &md5c, antpassword, 0xb );
            MD5_Final( md5hash, &md5c );        
        
            RC4_set_key( &rc4k, 0x10, md5hash );
            RC4( &rc4k, 0x10, &b[ hashesoffset + 0x10 + 8], obfkey );

            /* sf27 wrap to sf25 */
            sf27( obfkey, (int*)&rid, fb );

            for( i = 0; i < 0x10; i++ )
                printf( "%.2x", fb[i] );

            printf( ":::\n" );
        }
        else
            fprintf( stderr, "No password for user %s(%d)\n", username, rid );  

        free( username );
        free( keyname );
    }

    FreeLibrary( hinstLib ); 
    _RegCloseHive( &h );

    return 0;
}
