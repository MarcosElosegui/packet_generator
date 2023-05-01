#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "tcp_server.h"
#include "udp_server.h"

int main() 
{ 
    char username[15]; 
    char password[12];
    char protocolo[10];
    char port[20];
    
    printf("Introduce el usuario:\n");
    scanf("%s", username);
    
    printf("Introduce la contraseña:\n");
    scanf("%s", password);
    
    if(strcmp(username,"marcos")==0){ 
        if(strcmp(password,"marcos")==0){ 
            printf("\nBienvenido marcos!");
            printf("\nCon que protocolo quieres desplegar el servidor, ¿udp o tcp?:\n");
            scanf("%s", protocolo);
            printf("\n¿En que puerto quieres desplegar el servidor?:\n");
            scanf("%s", port);
            if(strcmp(protocolo,"udp")==0){
                udp_server(atoi(port));
            } else if(strcmp(protocolo,"tcp")==0) {
                tcp_server(atoi(port));
            } else {
                printf("%s no es un protocolo valido", protocolo);
                return 0;
            }
        }else{
            printf("\nContraseña incorrecta"); 
        } 
    }else{ 
        printf("\nEl usuario no existe"); 
    } 
    return 0; 
} 