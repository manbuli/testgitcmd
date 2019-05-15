// ***************************************************************
//  portRange.c   version:  1.0   date: 07/05/2015
//  Author:		WangShuiBing(shbwang@86nsn.org)
//  -------------------------------------------------------------
//  
//  -------------------------------------------------------------
//  Copyright (C) 2010 - 2015 SZWA  CO.,Ltd - All Rights Reserved
// ***************************************************************
// 
//  ChangeLog:
//
// ***************************************************************

//#ifdef PORT_RANGE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "portRange.h"

PortRange	g_PortRange;

int initPortRange(uint16 startPort, uint16 endPort, uint16 step)
{
	int i, j = 0;

	g_PortRange.step = step;
	g_PortRange.startPort = startPort;
	g_PortRange.endPort = endPort;

	for ( i = startPort; i < endPort; i += step )
	{
		if ( j < MAX_PORTRANGE )
		{
			g_PortRange.ports[j].flags = 0;

			if ( j == 0 )
			{
				g_PortRange.ports[j].lPort = startPort;
				g_PortRange.ports[j].hPort = startPort + step;
			}
			else
			{
				g_PortRange.ports[j].lPort = g_PortRange.ports[j - 1].hPort + 1;
				g_PortRange.ports[j].hPort = g_PortRange.ports[j].lPort + step - 1;
			}

			//debug(LOG_INFO, "i: %d, lport: %d, hport: %d", j,
			//		g_PortRange.ports[j].lPort, 
			//		g_PortRange.ports[j].hPort);

			j++;
		}
	}

	//debug(LOG_INFO, "%s startPort: %d, endPort: %d, step: %d, portRange Number: %d",
	//		__FUNCTION__, startPort, endPort, step, j);

	return 1;
}

int getPortRange(const u_char *macAddress, uint16 *lPort, uint16 *hPort)
{
	int i;

	for ( i = 0; i < MAX_PORTRANGE; i++ )
	{
		if ( g_PortRange.ports[i].flags == 0 )
		{
			*lPort = g_PortRange.ports[i].lPort;
			*hPort = g_PortRange.ports[i].hPort;
			g_PortRange.ports[i].flags = 1;

			memcpy(g_PortRange.ports[i].macAddress, macAddress, MAX_ALEN);

			//debug(LOG_INFO, "%s GET PORTRANGE mac: %02x:%02x:%02x, lPort: %d, hPort: %d, i = %d",
			//		__FUNCTION__, macAddress[3], macAddress[4], macAddress[5], 
			//		*lPort, *hPort, i);

			return 1;
		}
	}

	return 0;
}

int queryPortRangeByMacAddress(const u_char *macAddress, uint16 *lPort, uint16 *hPort)
{
	int i;

	for ( i = 0; i < MAX_PORTRANGE; i++ )
	{
		if ( g_PortRange.ports[i].flags == 1 &&
			memcmp(g_PortRange.ports[i].macAddress, macAddress, MAX_ALEN) == 0 )
		{
			*lPort = g_PortRange.ports[i].lPort;
			*hPort = g_PortRange.ports[i].hPort;

			//debug(LOG_INFO, "%s GET PORTRANGE by mac: %02x:%02x:%02x, lPort: %d, hPort: %d, i = %d",
			//		__FUNCTION__, macAddress[3], macAddress[4], macAddress[5], 
			//		*lPort, *hPort, i);

			return 1;
		}
	}

	return 0;
}

int updatePortRange(const u_char *macAddress)
{
	int i;

	for ( i = 0; i < MAX_PORTRANGE; i++ )
	{
		if ( g_PortRange.ports[i].flags == 1 &&
			memcmp(g_PortRange.ports[i].macAddress, macAddress, MAX_ALEN) == 0 )
		{
			g_PortRange.ports[i].flags = 0;

			//debug(LOG_INFO, "%s RELEASE PORTRANGE mac: %02x:%02x:%02x, lPort: %d, hPort: %d",
			//		__FUNCTION__, macAddress[3], macAddress[4], macAddress[5], 
			//		g_PortRange.ports[i].lPort, g_PortRange.ports[i].hPort);

			return 1;
		}
	}

	return 0;
}

//#endif
