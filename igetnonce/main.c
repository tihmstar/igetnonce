//
//  main.c
//  igetnonce
//
//  Created by tihmstar on 05.07.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "idevicerestore.h"
#include "common.h"

int64_t parseECID(const char *ecid){
    const char *ecidBK = ecid;
    int isHex = 0;
    int64_t ret = 0;
    
    while (*ecid && !isHex) {
        char c = *(ecid++);
        if (c >= '0' && c<='9') {
            ret *=10;
            ret += c - '0';
        }else{
            isHex = 1;
            ret = 0;
        }
    }
    
    if (isHex) {
        while (*ecidBK) {
            char c = *(ecidBK++);
            ret *=16;
            if (c >= '0' && c<='9') {
                ret += c - '0';
            }else if (c >= 'a' && c <= 'f'){
                ret += 10 + c - 'a';
            }else if (c >= 'A' && c <= 'F'){
                ret += 10 + c - 'A';
            }else{
                return 0; //ERROR parsing failed
            }
        }
    }
    
    return ret;
}

int main(int argc, const char * argv[]) {
    struct idevicerestore_client_t* client = idevicerestore_client_new();
    
    if (argc >= 3){
        if (strncmp(argv[1],"-e",2) == 0){
            if ((client->ecid = parseECID(argv[2])) == 0){
                printf("Error: can't parse ecid \"%s\", continuing without ecid\n",argv[2]);
            }else{
                printf("User specified ecid=%llx\n",client->ecid);
            }
        }
    }
    
    
    if (check_mode(client) < 0 || client->mode->index == MODE_UNKNOWN ||
        ((client->flags & FLAG_DOWNGRADE) && client->mode->index != MODE_DFU && client->mode->index != MODE_RECOVERY)) {
        error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
        return -1;
    }
    
    if (check_hardware_model(client) == NULL || client->device == NULL) {
        error("ERROR: Unable to discover device model\n");
        return -1;
    }
    
    info("Identified device as %s, %s ", client->device->hardware_model, client->device->product_type);
    
    
    switch (client->mode->index) {
        case MODE_NORMAL:
            info("in normal mode... ");
            break;
        case MODE_DFU:
            info("in dfu mode... ");
            break;
        case MODE_RECOVERY:
            info("in recovery mode... ");
            break;
            
        default:
            info("failed\n");
            error("ERROR: Device is in an invalid state\n");
            return -1;
    }
    info("\n");
    
    if ((client->flags & FLAG_PWN) && (client->mode->index != MODE_DFU)) {
        error("ERROR: you need to put your device into DFU mode to pwn it.\n");
        return -1;
    }
    
    if (!client->ecid && get_ecid(client, &client->ecid) < 0) {
        error("ERROR: Unable to find device ECID\n");
        return -1;
    }
    info("ecid=%llx\n",client->ecid);
    
    unsigned char* nonce = NULL;
    int nonce_size = 0;
    
    if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
        error("NOTE: Unable to get nonce from device\n");
    }
    if (get_sep_nonce(client, &nonce, &nonce_size) < 0) {
        error("NOTE: Unable to get nonce from device\n");
    }
    
    return 0;
}
