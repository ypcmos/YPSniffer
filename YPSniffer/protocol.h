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
	DWORD SrcAddr; // Դ��ַ
	DWORD DstAddr; // Ŀ�ĵ�ַ
	BYTE Mbz;      //��������0
	BYTE Ptcl;     //Э�飬��IPPROTO_TCP
	WORD Tcpl;     //TCP��ͷ����
}PSDHeader;
typedef PSDHeader * LPPSDHeader;
typedef PSDHeader UNALIGNED * ULPPSDHeader;

typedef struct _ARPFrame 
{
    WORD HWType;           //Ӳ������
    WORD ProtType;			//Э������
    BYTE HWAddrLen;		// Ӳ����ַ����
    BYTE ProtAddrLen;		// Э���ַ����
    WORD Opcode;            // ARP/RARP
    BYTE SendHWAddr[6];	// ����Ӳ����ַ
    BYTE SendProtAddr[4];	// ����Э���ַ
    BYTE TargHWAddr[6];	// ����Ӳ����ַ
    BYTE TargProtAddr[4];	// ����Э���ַ
    BYTE Padding[18];   // ����
}ARPFrame;
typedef ARPFrame * LPARPFrame;
typedef ARPFrame UNALIGNED * ULPARPFrame;

typedef struct _IPHeader
{
	union
	{ 
		BYTE Version; // �汾
		BYTE HdrLen; // IHL
	};
	BYTE ServiceType; // ��������
	WORD TotalLen; // �ܳ�
	WORD ID; // ��ʶ
	union
	{ 
		WORD Flags; // ��־
		WORD FragOff; // �ֶ�ƫ��
	};
	BYTE TimeToLive; // ������
	BYTE Protocol; // Э��
	WORD HdrChksum; // ͷУ���
	DWORD SrcAddr; // Դ��ַ
	DWORD DstAddr; // Ŀ�ĵ�ַ
	BYTE Options; // ѡ��
} IPHeader; 
typedef IPHeader * LPIPHeader;
typedef IPHeader UNALIGNED * ULPIPHeader;

typedef struct _IPv6Header
{
	union
	{
		DWORD version;               //�汾:4  
        DWORD flowtype;				//������  :8
		DWORD flowid;				//����ǩ  :20
	};
    WORD plen;                   //��Ч�غɳ���  
    BYTE nh;                      //��һ��ͷ��  
    BYTE hlim;                    //������  
    WORD saddr[8];           //Դ��ַ  
    WORD daddr[8];           //Ŀ�ĵ�ַ
}IPv6Header;
typedef IPv6Header * LPIPv6Header;
typedef IPv6Header UNALIGNED * ULPIPv6Header;

typedef struct _TCPHeader
{ 
	WORD SrcPort; // Դ�˿�
	WORD DstPort; // Ŀ�Ķ˿�
	DWORD SeqNum; // ˳���
	DWORD AckNum; // ȷ�Ϻ�
	BYTE DataOff; // TCPͷ��
	BYTE Flags; // ��־��URG��ACK�ȣ�
	WORD Window; // ���ڴ�С
	WORD Chksum; // У���
	WORD UrgPtr; // ����ָ��
} TCPHeader;
typedef TCPHeader *LPTCPHeader;
typedef TCPHeader UNALIGNED * ULPTCPHeader;

typedef struct _UDPHeader
{
	WORD SrcPort;	//Դ�˿�
	WORD DstPort;	//Ŀ�Ķ˿�
	WORD Len;		//�������
	WORD Chksum;	//У���
} UDPHeader;
typedef UDPHeader *LPUDPHeader;
typedef UDPHeader UNALIGNED * ULPUDPHeader;

typedef struct _ICMPHeader
{
	BYTE Type;		//��Ϣ����
	BYTE Code;		//����
	WORD Chksum;	//У���
	WORD ID;		//id
	WORD Seq;		//���к�
	DWORD Timestamp;	//ʱ���
} ICMPHeader;
typedef ICMPHeader *LPICMPHeader;
typedef ICMPHeader UNALIGNED * ULPICMPHeader;

typedef struct _ICMPv6Header
{
	BYTE type;            //8λ ����  
    BYTE code;            //8λ ����  
    BYTE seq;         //���к� 8λ  
    BYTE chksum;      //8λУ���  
    BYTE op_type; //ѡ�����  
    BYTE op_len;      //ѡ�����  
    BYTE op_ethaddr[6];       //ѡ���·���ַ  
} ICMPv6Header;
typedef ICMPv6Header *LPICMPv6Header;
typedef ICMPv6Header UNALIGNED * ULPICMPv6Header;

#ifdef __cplusplus
}
#endif

#endif //__PROTOCOL_H__