// SPDX-License-Identifier: GPL-2.0
#ifndef FUNCTION_H
#define FUNCTION_H

#include <stdio.h>
#include <linux/if_xdp.h>

/* This file contains the functions executed 
 * by the serverless framework. Please note that
 * the headers are already swapped. If a function
 * returns true, a packet will be sent with the 
 * content of pkt. If the application wants to 
 * use UDP Checksums, it can calculate them on their
 * own CPU time.
 */

typedef bool (*function)();

bool func_8883_getPayload (char *pkt, unsigned int *length,
                 const unsigned int header_length)
{
    //printf("Im der richtigen Funktion\n");

    const int iterations = (*length - header_length) >> 1;

    printf("Length: %d\n", *length);
    printf("Header Length: %d\n", header_length);
    printf("Payload length: %d\n", *length - header_length);

    for (int i = 0; i < iterations; i++) {
        printf("%c", pkt[header_length + i]);
    }

    printf("\n");

    return true;
}

function get_function(const unsigned int port)
{
	switch(port) {
	    case 8883:
		    return func_8883_getPayload;
		    break;

	    default:
		    return NULL;
		    break;
	}
	return NULL;
}

#endif
