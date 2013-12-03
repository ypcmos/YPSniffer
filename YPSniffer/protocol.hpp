#pragma once



class ProtocolBase: public CObject
{
	DECLARE_DYNCREATE(ProtocolBase)
public:
	ProtocolBase();
	virtual ~ProtocolBase();
};

class TransmissionPackage: public CObject
{
	DECLARE_DYNCREATE(TransmissionPackage)
public:
	TransmissionPackage(){data = NULL;}
	TransmissionPackage(BYTE *data, WORD datalen);
	virtual ~TransmissionPackage();
	BYTE* GetData(WORD &len) const;
	WORD GetDataLen() const;
private:
	BYTE *data;
	WORD datalen;
};

class IPv6: public ProtocolBase
{
	DECLARE_DYNCREATE(IPv6)
public:
	IPv6()
	{
		trans = NULL;
	}
	IPv6(BYTE version, BYTE flowtype, DWORD flowid, WORD plen, BYTE nh, BYTE hlim, CString saddr, CString daddr, TransmissionPackage *trans = NULL);
	~IPv6();
	BYTE GetVersion() const;
	BYTE GetFlowType() const;
	DWORD GetFlowId() const;
	WORD GetLen() const;
	BYTE GetNextHead() const;
	CString GetNextHeadString() const;
	BYTE GetJumpLimit() const;
	CString GetSrc() const;
	CString GetDst() const;
	TransmissionPackage * GetTrans() const;
	void SetTrans(TransmissionPackage * trans);
private:
	BYTE version;
	BYTE flowtype;
	DWORD flowid;
	WORD plen;
	BYTE nh;
	BYTE hlim;
	CString saddr, daddr;
	TransmissionPackage *trans;
};

class IPv4: public ProtocolBase
{
	DECLARE_DYNCREATE(IPv4)
public:
	IPv4()
	{
		trans = NULL;
	}
	IPv4(BYTE version, DWORD hdrLen, BYTE type, WORD len, WORD id, WORD flags, WORD fragOff, BYTE ttl, BYTE protocol, WORD hdrChksum, BYTE options, CString saddr, CString daddr, TransmissionPackage *trans = NULL);
	~IPv4();
	BYTE GetVersion() const;
	DWORD GetHeadLen() const;
	BYTE GetServiceType() const;
	WORD GetLen() const;
	WORD GetId() const;
	WORD GetFlags() const;
	WORD GetFragOff() const;
	BYTE GetTTL() const;
	BYTE GetProtocol() const;
	CString GetProtocolString() const;
	WORD GetHeadChksum() const;
	BYTE GetOptions() const;
	CString GetSrc() const;
	CString GetDst() const;
	TransmissionPackage * GetTrans() const;
	void SetTrans(TransmissionPackage * trans);
private:
	BYTE version; 
	DWORD hdrLen; 
	BYTE type;
	WORD len;
	WORD id; 
	WORD flags; 
	WORD fragOff; 
	BYTE ttl;
	BYTE protocol; 
	WORD hdrChksum;
	BYTE options;
	CString saddr, daddr;
	TransmissionPackage *trans;
};

class ARP: public ProtocolBase
{
	DECLARE_DYNCREATE(ARP)
public:
	ARP()
	{
		
	}
	ARP(WORD hwType, WORD protType, BYTE hwAddrLen, BYTE protAddrLen, WORD opcode, CString macsaddr, CString macdaddr, CString saddr, CString daddr);
	WORD GetHWType() const;           
    WORD GetProtType() const;			
    BYTE GetHWAddrLen() const;		
    BYTE GetProtAddrLen() const;		
    WORD GetOpcode() const;   
	CString GetSrc() const;
	CString GetDst() const;
	CString GetMacSrc() const;
	CString GetMacDst() const;
private:
	WORD hwType;           //硬件类型
    WORD protType;			//协议类型
    BYTE hwAddrLen;		// 硬件地址长度
    BYTE protAddrLen;		// 协议地址长度
    WORD opcode;            // ARP/RARP
	CString saddr, daddr;
	CString macsaddr, macdaddr;
};
	
class PPPoE: public ProtocolBase
{
	DECLARE_DYNCREATE(PPPoE)
public:
	PPPoE(){next = NULL;}
	~PPPoE()
	{
		if (next != NULL)
		{
			delete next;
		}
	}
	PPPoE(BYTE version, BYTE type, BYTE code, WORD sessionID, WORD len, WORD ppp_type, ProtocolBase *next = NULL);
	BYTE GetVersion() const;
	BYTE GetType() const;	
	BYTE GetCode() const;
	WORD GetSessionID() const;
	WORD GetLen() const;
	void SetNext(ProtocolBase *next);
	ProtocolBase *GetNext() const;
	CString GetTypeString() const;
	WORD GetPPPType() const;
	CString GetPPPTypeString() const;
private:
	BYTE version;
	BYTE type;	
	BYTE code;
	WORD sessionID;
	WORD len;
	ProtocolBase *next;
	WORD ppp_type;
};

class UDP: public TransmissionPackage
{
	DECLARE_DYNCREATE(UDP)
public:
	UDP(): TransmissionPackage(){}
	UDP(WORD sport, WORD dport, WORD len, WORD chksum, BYTE *data, WORD datalen);
	~UDP();
	WORD GetSport() const;
	WORD GetDport()  const;
	WORD GetLen() const;
	WORD GetChksum() const;
private:
	WORD sport;
	WORD dport;
	WORD len;
	WORD chksum;
};

class TCP: public TransmissionPackage
{
	DECLARE_DYNCREATE(TCP)
public:
	TCP(): TransmissionPackage(){}
	TCP(WORD sport, WORD dport, DWORD seqnum, DWORD acknum, WORD hlen, BYTE flags, WORD window, WORD chksum, WORD urgptr, BYTE *data, WORD datalen);
	~TCP();
	WORD GetSport() const;
	WORD GetDport() const;
	DWORD GetSeqNum() const;
	DWORD GetAckNum() const;
	WORD GetHLen() const; 
	BYTE GetFlags() const; 
	WORD GetWindowSize() const; 
	WORD GetChksum() const; 
	WORD GetUrgPtr() const; 
	CString GetFlagsString() const;
	CString GetSimpleProtocolString() const;
private:
	WORD sport;
	WORD dport;
	DWORD seqnum;
	DWORD acknum;
	WORD hlen; 
	BYTE flags; 
	WORD window; 
	WORD chksum; 
	WORD urgptr; 
};

class EthHeader
{
public:
	EthHeader(CString src, CString dst, WORD type, ProtocolBase * protocol = NULL);
	~EthHeader();
	CString GetSource() const;
	CString GetDestnation() const;
	CString GetTypeString() const;
	WORD GetType() const;
	ProtocolBase * GetProtocol() const;
	void SetProtocol(ProtocolBase * protocol);
private:
	CString src, dst;
	WORD type;
	ProtocolBase * protocol;
};

class Frame
{
public:
	Frame();
	Frame(EthHeader* eth, CString time, DWORD len);
	~Frame();
	CString GetTime() const;
	DWORD GetLen() const;
	EthHeader* GetEthHeader() const;
private:
	EthHeader* eth;
	CString time;
	DWORD len;
};