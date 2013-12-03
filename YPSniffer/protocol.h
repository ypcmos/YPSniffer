#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_PROTOCOL_IP 0x0800
#define ETH_PROTOCOL_IPV6 0x86dd
#define ETH_PROTOCOL_ARP 0x0806
#define ETH_PROTOCOL_RARP 0x8035
#define ETH_PROTOCOL_PPP_DISCOVERY 0x8863
#define ETH_PROTOCOL_PPP_SESSION 0x8864
#define ETH_PROTOCOL_AARP 0x80F3
#define ETH_PROTOCOL_EAPS 0x8100
#define ETH_PROTOCOL_IPX 0x8137
#define ETH_PROTOCOL_SNMP 0x814C

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_ICMPV6 0x3a
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

#define	PPP_LCP 0xc021
#define PPP_PAP 0xc023
#define PPP_CHAP 0xc223
#define PPP_IPCP 0x8021
#define PPP_IP 0x0021

typedef struct _ETHHeader
{
	BYTE  Dst[6];
	BYTE  Src[6];
	WORD Type;
}ETHHeader;
typedef ETHHeader * LPETHHeader;
typedef ETHHeader UNALIGNED * ULPETHHeader;

typedef struct _PPPoEHeader
{
	union
	{
		BYTE Version;
		BYTE Type;
	};
	BYTE Code;
	WORD SessionID;
	WORD Len;
	WORD ppp_type;
}PPPoEHeader;
typedef PPPoEHeader * LPPPPoEHeader;
typedef PPPoEHeader UNALIGNED * ULPPPPoEHeader;

typedef struct _PSDHeader
{
	DWORD SrcAddr; // 源地址
	DWORD DstAddr; // 目的地址
	BYTE Mbz;      //保留，置0
	BYTE Ptcl;     //协议，如IPPROTO_TCP
	WORD Tcpl;     //TCP报头长度
}PSDHeader;
typedef PSDHeader * LPPSDHeader;
typedef PSDHeader UNALIGNED * ULPPSDHeader;

typedef struct _ARPFrame 
{
    WORD HWType;           //硬件类型
    WORD ProtType;			//协议类型
    BYTE HWAddrLen;		// 硬件地址长度
    BYTE ProtAddrLen;		// 协议地址长度
    WORD Opcode;            // ARP/RARP
    BYTE SendHWAddr[6];	// 发送硬件地址
    BYTE SendProtAddr[4];	// 发送协议地址
    BYTE TargHWAddr[6];	// 接收硬件地址
    BYTE TargProtAddr[4];	// 接收协议地址
    BYTE Padding[18];   // 对齐
}ARPFrame;
typedef ARPFrame * LPARPFrame;
typedef ARPFrame UNALIGNED * ULPARPFrame;

typedef struct _IPHeader
{
	union
	{ 
		BYTE Version; // 版本
		BYTE HdrLen; // IHL
	};
	BYTE ServiceType; // 服务类型
	WORD TotalLen; // 总长
	WORD ID; // 标识
	union
	{ 
		WORD Flags; // 标志
		WORD FragOff; // 分段偏移
	};
	BYTE TimeToLive; // 生命期
	BYTE Protocol; // 协议
	WORD HdrChksum; // 头校验和
	DWORD SrcAddr; // 源地址
	DWORD DstAddr; // 目的地址
	BYTE Options; // 选项
} IPHeader; 
typedef IPHeader * LPIPHeader;
typedef IPHeader UNALIGNED * ULPIPHeader;

typedef struct _IPv6Header
{
	union
	{
		DWORD version;               //版本:4  
        DWORD flowtype;				//流类型  :8
		DWORD flowid;				//流标签  :20
	};
    WORD plen;                   //有效载荷长度  
    BYTE nh;                      //下一个头部  
    BYTE hlim;                    //跳限制  
    WORD saddr[8];           //源地址  
    WORD daddr[8];           //目的地址
}IPv6Header;
typedef IPv6Header * LPIPv6Header;
typedef IPv6Header UNALIGNED * ULPIPv6Header;

typedef struct _TCPHeader
{ 
	WORD SrcPort; // 源端口
	WORD DstPort; // 目的端口
	DWORD SeqNum; // 顺序号
	DWORD AckNum; // 确认号
	BYTE DataOff; // TCP头长
	BYTE Flags; // 标志（URG、ACK等）
	WORD Window; // 窗口大小
	WORD Chksum; // 校验和
	WORD UrgPtr; // 紧急指针
} TCPHeader;
typedef TCPHeader *LPTCPHeader;
typedef TCPHeader UNALIGNED * ULPTCPHeader;

typedef struct _UDPHeader
{
	WORD SrcPort;	//源端口
	WORD DstPort;	//目的端口
	WORD Len;		//封包长度
	WORD Chksum;	//校验和
} UDPHeader;
typedef UDPHeader *LPUDPHeader;
typedef UDPHeader UNALIGNED * ULPUDPHeader;

typedef struct _ICMPHeader
{
	BYTE Type;		//消息类型
	BYTE Code;		//代码
	WORD Chksum;	//校验和
	WORD ID;		//id
	WORD Seq;		//序列号
	DWORD Timestamp;	//时间戳
} ICMPHeader;
typedef ICMPHeader *LPICMPHeader;
typedef ICMPHeader UNALIGNED * ULPICMPHeader;

typedef struct _ICMPv6Header
{
	BYTE type;            //8位 类型  
    BYTE code;            //8位 代码  
    BYTE seq;         //序列号 8位  
    BYTE chksum;      //8位校验和  
    BYTE op_type; //选项：类型  
    BYTE op_len;      //选项：长度  
    BYTE op_ethaddr[6];       //选项：链路层地址  
} ICMPv6Header;
typedef ICMPv6Header *LPICMPv6Header;
typedef ICMPv6Header UNALIGNED * ULPICMPv6Header;

#ifdef __cplusplus
}
#endif

#endif //__PROTOCOL_H__