#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "aes256.h"
#include "b64.h"

typedef struct Pwd Pwd;

int status = 0;
int login = 0;
uint8_t key[32];

struct Pwd
{
    char descrip[100];
    char usuario[100];
    char passwd[100];
    Pwd *siguiente;
};

int gestionaError(sqlite3 *db)
{
    fprintf(stderr, "ERROR: %s\n", sqlite3_errmsg(db));
    return sqlite3_errcode(db);
}


char *cifradoAES256(char buf[])
{   
    aes256_context ctx; 
    //uint8_t key[32];
    char i;
    aes256_init(&ctx, key);
    aes256_encrypt_ecb(&ctx, buf);
    aes256_done(&ctx);
    return buf;
} 

char *descifradoAES256(char buf[])
{
    aes256_context ctx; 
    //uint8_t key[32];
    char i;
    aes256_init(&ctx, key);
    aes256_decrypt_ecb(&ctx, buf);
    aes256_done(&ctx);
    return buf;
} 


int callback(void *ptr, int numeroDeColumnas, char **valoresCeldas, char **nombresDeColumnas)
{
    (void) ptr;
    int ix;
    for (ix = 0; ix < numeroDeColumnas; ++ix)
    {
        if(*(char *)nombresDeColumnas[ix] == *(char *)"hash")
        {
            status = 1;
        }
        if(*(char *)nombresDeColumnas[ix] == *(char *)"hash" && *(char *)valoresCeldas[ix] != *(char *)"")
        {
            login = 1;
            /*char *temp2;
            char *temp = valoresCeldas[ix];
            char *dec = b64_decode(temp, strlen(temp));
            descifradoAES256((char*)dec);
            free(dec);
            strcat(temp2, dec);
            strcat(temp2, dec);
            printf("%s", temp2);
            key = temp2;
            free(dec);*/
        }
        else if (*(char *)nombresDeColumnas[ix] == *(char *)"descrip")	
        {
            printf("%s", valoresCeldas[ix]);
            printf("\n");
        }
        else if (numeroDeColumnas == 3)
        {
            if (*(char *)nombresDeColumnas[ix] == *(char *)"passwd")
            {
                char *temp = valoresCeldas[ix];
                char *dec = b64_decode(temp, strlen(temp));
                descifradoAES256((char*)dec);
                printf("%s", dec);
                printf("\n");
                free(dec);
            }
            else
            {
                printf("%s", valoresCeldas[ix]);
                printf("\n");
            }
            
        }
    }
    return 0;
}

void leeBaseDatos(sqlite3 *db)
{
    sqlite3_exec(db, "SELECT * FROM cuentas", callback, NULL, NULL);
}

void leeDescrip(sqlite3 *db)
{
    printf("\n");
    printf("CUENTAS: \n\n");
    sqlite3_exec(db, "SELECT descrip FROM cuentas", callback, NULL, NULL);
    printf("\n");
}

void mostrarCuenta(sqlite3 *db)
{
    char descrip[100];
    scanf("%s", descrip);
    char sql[140] = "SELECT * FROM cuentas WHERE descrip = '";
    strcat(descrip, "'");
    strcat(sql, descrip);
    printf("\n");
    printf("CUENTA: \n\n");
    sqlite3_exec(db, sql, callback, NULL, NULL);
    printf("\n");
}

void insertarCuenta(sqlite3 *db)
{
    char descrip[100];
    char usuario[100];
    char passwd[100];
    scanf("%s", descrip);
    scanf("%s", usuario);
    scanf("%s", passwd);
    cifradoAES256(passwd);
    char *enc = b64_encode(passwd, strlen(passwd));
    char sql[140] = "INSERT INTO cuentas(descrip, usuario, passwd) VALUES('";
    strcat(descrip, "','");
    strcat(descrip, usuario);
    strcat(descrip, "','");
    strcat(descrip, enc);
    strcat(descrip, "')");
    strcat(sql, descrip);
    //printf("%s", sql);
    sqlite3_exec(db, sql, callback, NULL, NULL);
    printf("\n");
    printf("Cuenta Agregada Exitosamente.");
    printf("\n");
    free(enc);
}

void borrarCuenta(sqlite3 *db)
{
    char descrip[100];
    scanf("%s", descrip);
    char sql[140] = "DELETE FROM cuentas WHERE descrip = '";
    strcat(descrip, "'");
    strcat(sql, descrip);
    sqlite3_exec(db, sql, callback, NULL, NULL);
    printf("\n");
    printf("Cuenta Borrada");
    printf("\n");
}

void menuConfiguracion(sqlite3 *db)
{

    char pass[16];
    puts("");
    puts("                PWM                 ");
    puts("");
    puts("    Pantalla de Configuración       ");
    puts("");
    puts("Bienvenido al sistema PassWord      ");
    puts("Manager en esta pantalla se activa  ");
    puts("y configura el password que servira ");
    puts("para el acceso y cifrado de la      ");
    puts("información, la contraseña propor-  ");
    puts("cionada debera tener una longitud de");
    puts("16 caracteres.                      ");
    puts("");
    puts("            Advertencia             ");
    puts("");
    puts("Si la contraseña se llegara a extra-");
    puts("viar, ya no se podra tener acceso   ");
    puts("al sistema ni a los datos.");
    puts("");
    printf("\n");
    printf("Introduzca su Contraseña:");
    printf("\n");
    scanf("%s", pass);
    cifradoAES256(pass);
    printf("%s\n", pass);
    char *enc = b64_encode(pass, strlen(pass));
    char sql[] = "INSERT INTO usuarios(hash) VALUES('";
    strcat(sql, enc);
    strcat(sql, "')");
    sqlite3_exec(db, sql, callback, NULL, NULL);
    //printf("%s", sql);
    printf("\n");
    printf("Configuración Finalizada.\n");
    printf("\n");
    printf("Vuelva a Ejecutar el Programa\n");
    printf("Para Validar su Contraseña.\n");
    printf("\n");
    free(enc);
}

void usuarioNull()
{
    sqlite3 *db = NULL;
    const char *filenameDatabase = "pwm.db";
    if(sqlite3_open(filenameDatabase, &db) != SQLITE_OK)
    {
        gestionaError(db);
    }
    char sql[] = "SELECT * FROM usuarios";
    sqlite3_exec(db, sql, callback, NULL, NULL);
    if(status == 0)
    {   
        menuConfiguracion(db);
        exit(0);
    }
    else
    {
        // login
        char sql[] = "SELECT * FROM usuarios";
        sqlite3_exec(db, sql, callback, NULL, NULL);
       
    }
    sqlite3_close(db);
}

void validarLogin()
{
    sqlite3 *db = NULL;
    const char *filenameDatabase = "pwm.db";
    if(sqlite3_open(filenameDatabase, &db) != SQLITE_OK)
    {
        gestionaError(db);
    }
    char pass[16];
    printf("Introduzca su Contraseña de Acceso\n");
    scanf("%s", pass);
    cifradoAES256(pass);
    char *enc = b64_encode(pass, strlen(pass));
    char sql[] = "SELECT hash FROM usuarios Where hash = '";
    strcat(sql, enc);
    strcat(sql, "')");
    printf("\n");
    sqlite3_exec(db, sql, callback, NULL, NULL);
    if(login != 1)
    {   
        exit(0);
    }
}

void pantallaInicio()
{
    puts("                                                                           ");
    puts("                                                                           ");
    puts("                                    ```                                    ");
    puts("                                `/ydddddy/`                                ");
    puts("                               /dmmmmmmmmmdo`                              ");
    puts("                              -mmmmmmmmmmmmmd+`                            ");
    puts("                       .:/++//smmmmmd+/smmmmmmd+`                          ");
    puts("                     .++++++++hmmmmmo   -smmmmmmd+`                        ");
    puts("                    .o++++++++ymmmmmo`    -ymmmmmmh/                       ");
    puts("                    /+++++o//+hmmmmmy+:.    -ymmdyoo                       ");
    puts("                    ++++++s  `ommmmmy++++-`  -sso++o                       ");
    puts("                    ++++++s   ommmmmy++++++/+o+++++o                       ");
    puts("                    ++++++s   ommmmmy+++++++oooo+o+:                       ");
    puts("                    ++++++s   ommmmm+-ooo++++++oo+.                        ");
    puts("                    ++++++s   ommmmds+++oooo+++++oo/                       ");
    puts("                    ++++++s   omdhso+++++oo/++++osdh                       ");
    puts("                    ++++++s  `oyo++++++++-`  ./ydmmh                       ");
    puts("                    /+++++o//+o+++++o+:.    `:ymmmmh                       ");
    puts("                    .o+++++++++++osyo`    `:ymmmmmh/                       ");
    puts("                     .+++++++++oydmm+   `:ymmmmmh+`                        ");
    puts("                       .://+//odmmmmy..:ymmmmmd+.                          ");
    puts("                              -mmmmmmddmmmmmd+.                            ");
    puts("                               /dmmmmmmmmmdo.                              ");
    puts("                                ./yhdddhy/.                                ");
    puts("                                   ``.``                                   ");
    puts("                                                                           ");
    puts("                                                                           ");
    puts("                                    PWM                                    ");
    puts("                                                                           ");
    puts("                                                                           ");
    puts("                 Teclea  h  para desplegar el menu de ayuda                ");
    puts("                                                                           ");
    puts("                                                                           ");
}

void acercaDe()
{
    puts("");
    puts("Zacatecas, Zac. 16 de Marzo de 2018.");
    puts("");
    puts("El programa PassWordManager fue     ");
    puts("desarrollado como proyecto final de ");
    puts("de la materia de Seguridad en       ");
    puts("Sistemas de Información del Centro  ");
    puts("de Investigación en Matemáticas, en ");
    puts("su primera version solo se incluye  ");
    puts("la versión de consola, utilizando   ");
    puts("el algoritmos AES256 para la        ");
    puts("protección de la intrusión no       ");
    puts("autorizada y el cifrado de los      ");
    puts("datos.                              ");
    puts("");
    puts("  https://github.com/josscimat/PWM  ");
    puts("");
}

void pantallaAyuda()
{
    puts("");
    puts("PWM v1.0");
    puts("");   
    puts("Bienvenido al menú de ayuda de");
    puts("       PassWordManager        ");
    puts("");
    puts("Mostrar todas las Cuentas: t");
    puts("");
    puts("Mostrar el Password de una Cuenta:");
    puts("p<nombre_de_la_cuenta>");   
    puts("");   
    puts("Insertar una nueva Cuenta:");
    puts("i<enter>");
    puts("<nombre_de_la_cuenta><enter>");
    puts("<usuario><enter>");
    puts("<contraseña><enter>");   
    puts("");    
    puts("Eliminar una Cuenta:");
    puts("e<nombre_de_la_cuenta>");      
    puts(""); 
    puts("Acerca de: a");      
    puts(""); 
    puts("Salir del Programa: qq");
    puts("");             
}

char cicloSeleccion()
{
    char input;
    Pwd pwd;
    Pwd *lista = NULL;
    sqlite3 *db = NULL;
    const char *filenameDatabase = "pwm.db";
    if(sqlite3_open(filenameDatabase, &db) != SQLITE_OK)
    {
        gestionaError(db);
    }
    printf(">");
    input = getchar();
    switch(input)
    {
        case 't':
            // lectura de la descripcion de la tabla cuentas
            leeDescrip(db);
            break;
        case 'p':
            // lectura de los campos de una cuenta
            mostrarCuenta(db);
            break;
        case 'i':
            // inserta una nueva cuenta
            insertarCuenta(db);
            break;
        case 'e':
            // borra una cuenta
            borrarCuenta(db);
            break;
        case 'a':
            acercaDe();
            break;
        case 'h':
            pantallaAyuda();
            break;
        case 'q':
            break;
        default:
            // cerrar base de datos
    	    sqlite3_close(db);
    }
    return input; 
}

int main()
{
    // configuracion de inicio
    usuarioNull();
    
    // login del sistema
    validarLogin();

    // pantalla de inicio
    pantallaInicio();

    // Ciclo de seleccion de opcion
    while (cicloSeleccion() != 'q')
    {
        cicloSeleccion();    
    }


    
/*
    // lectura de toda la base de datos
    leeBaseDatos(db);
*/  


    return 0;
}
