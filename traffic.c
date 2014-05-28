#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "basetype.h"

/* 网卡名称最大长度 */
#define DEVICE_NAME_LEN (1024)

/* 过滤条件最大长度 */
#define FILTER_LEN (10 * 1024)

/* 当前选择抓包的网卡索引及名称 */
UINT32 g_uiDeviceIndex = -1;
CHAR g_acDeviceName[DEVICE_NAME_LEN + 1] = {0};

/* 条件过滤器 */
CHAR g_acFilter[FILTER_LEN + 1] = {0};

/* 报文处理回调函数 */
VOID traffic_callback(UINT8 *pucCntx, const struct pcap_pkthdr *pstPktHdr, const UINT8 *pucPacket);

/* 主函数 */
int main(int argc, char *argv[])
{
    CHAR *pcDev = NULL;
    CHAR acErrBuff[PCAP_ERRBUF_SIZE] = {0};
    INT32 iLoop = 0;
    
    UINT32 uiShowUsageOnly = NO;
    INT32 iRet = 0;

    pcap_t *pstHandle = NULL;
    pcap_if_t *pstAllDevices = NULL;
    pcap_if_t *pstDevice = NULL;

    struct bpf_program stFilter = {0};
    bpf_u_int32 uiIP = 0;
    bpf_u_int32 uiNetmask = 0;

    /* 0.命令行参数处理 */
    if (1 >= argc)
    {
        uiShowUsageOnly = YES;
    }
    else if (2 == argc)
    {
        g_uiDeviceIndex = atoi(argv[1]);
    }
    else /* 3 <= argc */
    {
        g_uiDeviceIndex = atoi(argv[1]);
        strncpy(g_acFilter, argv[2], FILTER_LEN);
        DEBUG_EVENT("Set filter: %s", g_acFilter);
    }

    /* 1.查找所有的网卡接口 */
    iRet = pcap_findalldevs(&pstAllDevices, acErrBuff);
    if (OK != iRet)
    {
        DEBUG_ERROR("Could not find any device! (%s)", acErrBuff);
        return ERROR;
    }

    /* 2.打印网卡接口列表 */
    iLoop = 0;
    pstDevice = pstAllDevices;
    DEBUG_INFO("Device list:");
    while (NULL != pstDevice)
    {
        if (g_uiDeviceIndex == iLoop)
        {
            DEBUG_INFO(" -> (%d) %s (%s)", iLoop, pstDevice->name, pstDevice->description);
            strncpy(g_acDeviceName, pstDevice->name, DEVICE_NAME_LEN);
        }
        else
        {
            DEBUG_INFO("    (%d) %s (%s)", iLoop, pstDevice->name, pstDevice->description);
        }
        pstDevice = pstDevice->next;
        ++iLoop;
    }

    pcap_freealldevs(pstAllDevices);
    pstAllDevices = NULL;

    if (YES == uiShowUsageOnly)
    {
        DEBUG_INFO("Usage:");
        DEBUG_INFO("    traffic <Device Index> [Filter] ");
        return OK;
    }

    if (0 == strlen(g_acDeviceName))
    {
        DEBUG_ERROR("Could not found the selected device(%u)!", g_uiDeviceIndex);
        return OK;
    }

    DEBUG_EVENT("Select device: (%u) %s", g_uiDeviceIndex, g_acDeviceName);

    /* 3.查询网卡信息(IP/Mask) */
    iRet = pcap_lookupnet(g_acDeviceName, &uiIP, &uiNetmask, acErrBuff);
    if (OK != iRet)
    {
        DEBUG_ERROR("Could not get the device infomation! (%s)", acErrBuff);
        uiIP = 0;
        uiNetmask = 0;

        /* 查询网卡信息失败不影响业务功能 继续处理 */
    }

    /* 4.打开指定的网卡 */
    /*   参数1:网卡名称 参数2:最大数据长度 参数3:超时时间(ms) 参数4:错误信息 */
    pstHandle = pcap_open_live(g_acDeviceName, 65535, 1, 500, acErrBuff);
    if (NULL == pstHandle)
    {
        DEBUG_ERROR("Could not open device %s! (%s)", g_acDeviceName, acErrBuff);
        return ERROR;
    }

    /* 5.设置过滤条件 */
    /*   参数1:网卡句柄 参数2:过滤器 参数3:过滤条件字符串 参数4:是否优化 参数5:网络掩码 */
    iRet = pcap_compile(pstHandle, &stFilter, g_acFilter, 0, uiNetmask);
    if (OK != iRet)
    {
        DEBUG_ERROR("Could not parse the filter \"%s\"! (%s)", g_acFilter, pcap_geterr(pstHandle));
        return ERROR;
    }
    iRet = pcap_setfilter(pstHandle, &stFilter);
    if (OK != iRet)
    {
        DEBUG_ERROR("Could not set the filter \"%s\"! (%s)", g_acFilter, pcap_geterr(pstHandle));
        return ERROR;
    }

    /* 6.抓包处理 */
    /*   参数1:网卡句柄 参数2:报文个数 参数3:回调函数 参数4:上下文信息 */
    pcap_loop(pstHandle, -1, traffic_callback, NULL);

    /* 7.关闭网卡 */
    pcap_close(pstHandle);
    pstHandle = NULL;

    return OK;
}

/* 报文处理回调函数 */
VOID traffic_callback(UINT8 *pucCntx, const struct pcap_pkthdr *pstPktHdr, const UINT8 *pucPacket)
{
    DEBUG_EVENT("Receives a packet (%u bytes).", pstPktHdr->len);

    return;
}

