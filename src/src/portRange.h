// ***************************************************************
//  portRange.h   version:  1.0   date: 07/05/2015
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

#ifndef _PORTRANGE_H
#define _PORTRANGE_H

#include <stdio.h>
#include <stdlib.h>

#ifndef uint16
typedef unsigned short uint16;
#endif

#define MAX_ALEN 6

#define PR_STARTPORT		10000
#define PR_ENDPORT			65000
#define PR_STEP					1000
#define PR_UDPPORT			100

#define MAX_PORTRANGE	128
typedef struct _Port
{
	u_char macAddress[MAX_ALEN];
	uint16 lPort;
	uint16 hPort;
	char flags;
} Port;

typedef struct _PortRange
{
	Port	 ports[MAX_PORTRANGE];
	uint16 step;
	uint16 startPort;
	uint16 endPort;

} PortRange;


// 初始化端口池，程序启动时调用。
// @startPort，起始端口号，使用PR_STARTPORT
// @endPort，结束端口号，使用PR_ENDPORT
// @step，每个节点使用的端口数，如果连接的用户量不多，可以设大一点，如果用户较多，可以设置小一点，默认是PR_STEP
int initPortRange(uint16 startPort, uint16 endPort, uint16 step);


// 从端口池中获取起始端口和结束端口，用户上线在使用iptables设置源外网端口之前调用
// @macAddress，手机终端的MAC地址
// @lPort，获取的起始端口
// @hPort，获取的结束端口
//
// Return: 1：获取成功，0：获取失败，端口已全部用完。
int getPortRange(const u_char *macAddress, uint16 *lPort, uint16 *hPort);


// 释放端口到端口池，用户下线的时候调用
// @macAddress，手机终端的MAC地址
int updatePortRange(const u_char *macAddress);

// 根据MAC地址在端口池中查找起始端口和结束端口
// @macAddress，手机终端的MAC地址
// @lPort，获取的起始端口
// @hPort，获取的结束端口
//
// Return: 1：查找成功，0：查找失败。
int queryPortRangeByMacAddress(const u_char *macAddress, uint16 *lPort, uint16 *hPort);

#endif

//#endif
