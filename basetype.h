#ifndef _BASETYPE_H_
#define _BASETYPE_H_

#define OK                          (0)
#define ERROR                       (1)

#define YES                         (1)
#define NO                          (0)

typedef void                        VOID;

typedef char                        CHAR;
typedef char                        INT8;
typedef short                       INT16;
typedef int                         INT32;
typedef long long                   INT64;
typedef long                        LONG;

typedef unsigned char               UCHAR;
typedef unsigned char               UINT8;
typedef unsigned short              UINT16;
typedef unsigned int                UINT32;
typedef unsigned long long          UINT64;
typedef unsigned long               ULONG;

#define DEBUG_INFO(fmt, ...)        printf("[Info] "fmt"\r\n", ##__VA_ARGS__)
#define DEBUG_EVENT(fmt, ...)       printf("[Event] "fmt"\r\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...)       printf("[Error] "fmt"\r\n", ##__VA_ARGS__)

#endif /* _BASETYPE_H__ */

