#include "stdafx.h"
#include "protocol.hpp"

EthHeader::EthHeader(CString src, CString dst, WORD type, ProtocolBase *protocol)
{
	this->src = src;
	this->dst = dst;
	this->type = type;
	this->protocol = protocol;
}

CString EthHeader::GetSource() const
{
	return src;
}

CString EthHeader::GetDestnation() const
{
	return dst;
}

CString EthHeader::GetTypeString() const
{
	CString ret;
	switch(type)
	{
	case ETH_PROTOCOL_IP:
		ret = "IPv4";
		break;
	case ETH_PROTOCOL_IPV6:
		ret = "IPv6";
		break;
	case ETH_PROTOCOL_ARP:
		ret = "ARP";
		break;
	case ETH_PROTOCOL_RARP:
		ret = "RARP";
		break;
	case ETH_PROTOCOL_PPP_DISCOVERY:
		ret = "PPP(D)";
		break;
	case ETH_PROTOCOL_PPP_SESSION:
		ret = "PPP(S)";
		break;
	case ETH_PROTOCOL_AARP:
		ret = "AARP";
		break;
	case ETH_PROTOCOL_EAPS:
		ret = "EAPS";
		break;
	case ETH_PROTOCOL_IPX:
		ret = "IPX";
		break;
	case ETH_PROTOCOL_SNMP:
		ret = "SNMP";
		break;
	default:	
		ret.Format("%4x", type);	
		break;
	}
	return ret;
}

WORD EthHeader::GetType() const
{
	return type;
}

ProtocolBase * EthHeader::GetProtocol() const
{
	return protocol;
}

void EthHeader::SetProtocol(ProtocolBase * protocol)
{
	this->protocol = protocol;
}

EthHeader::~EthHeader()
{
	if (protocol != NULL)
	{
		delete protocol;
	}
}

Frame::Frame()
{
	this->eth = NULL;
}

Frame::Frame(EthHeader* eth, CString time, DWORD len)
{
	this->eth = eth;
	this->time = time;
	this->len = len;
}

Frame::~Frame()
{
	if (eth != NULL)
	{
		delete eth;
	}
}

CString Frame::GetTime() const
{
	return time;
}

DWORD Frame::GetLen() const
{
	return len;
}

EthHeader* Frame::GetEthHeader() const
{
	return eth;
}

IMPLEMENT_DYNCREATE(ProtocolBase, CObject)

ProtocolBase::ProtocolBase()
{
}

ProtocolBase::~ProtocolBase()
{
}

IMPLEMENT_DYNCREATE(IPv6, ProtocolBase)

IPv6::IPv6(BYTE version, BYTE flowtype, DWORD flowid, WORD plen, BYTE nh, BYTE hlim, CString saddr, CString daddr, TransmissionPackage *trans)
{
	this->version = version;
	this->flowtype = flowtype;
	this->flowid = flowid;
	this->plen = plen;
	this->nh = nh;
	this->hlim = hlim;
	this->saddr = saddr;
	this->daddr = daddr;
	this->trans = trans;
}

IPv6::~IPv6()
{
	if (trans != NULL)
	{
		delete trans;
	}
}

BYTE IPv6::GetVersion() const
{
	return version;
}

BYTE IPv6::GetFlowType() const
{
	return flowtype;
}

DWORD IPv6::GetFlowId() const
{
	return flowid;
}

WORD IPv6::GetLen() const
{
	return plen;
}

BYTE IPv6::GetNextHead() const
{
	return nh;
}

BYTE IPv6::GetJumpLimit() const
{
	return hlim;
}

CString IPv6::GetSrc() const
{
	return saddr;
}

CString IPv6::GetDst() const
{
	return daddr;
}

TransmissionPackage * IPv6::GetTrans() const
{
	return trans;
}

void IPv6::SetTrans(TransmissionPackage * trans)
{
	this->trans = trans;
}

CString IPv6::GetNextHeadString() const
{
	CString ret;
	switch(nh)
	{
	case IP_PROTOCOL_ICMPV6:
		ret = "ICMPv6";
		break;
	case IP_PROTOCOL_TCP:
		ret = "TCP";
		break;
	case IP_PROTOCOL_UDP:
		ret = "UDP";
		break;
	default:	
		ret.Format("%4x", nh);	
		break;
	}
	return ret;
}


IMPLEMENT_DYNCREATE(IPv4, ProtocolBase)
IPv4::IPv4(BYTE version, DWORD hdrLen, BYTE type, WORD len, WORD id, WORD flags, WORD fragOff, BYTE ttl, BYTE protocol, WORD hdrChksum, BYTE options, CString saddr, CString daddr, TransmissionPackage *trans)
{
	this->version = version;
	this->hdrLen = hdrLen;
	this->type = type;
	this->len = len;
	this->id = id;
	this->flags = flags;
	this->fragOff = fragOff;
	this->ttl = ttl;
	this->protocol = protocol;
	this->hdrChksum = hdrChksum;
	this->options = options;
	this->saddr = saddr;
	this->daddr = daddr;
	this->trans = trans;
}

IPv4::~IPv4()
{
	if (trans != NULL)
	{
		delete trans;
	}
}

BYTE IPv4::GetVersion() const
{
	return version;
}

void IPv4::SetTrans(TransmissionPackage * trans)
{
	this->trans = trans;
}

DWORD IPv4::GetHeadLen() const
{
	return hdrLen;
}

BYTE IPv4::GetServiceType() const
{
	return type;
}

WORD IPv4::GetLen() const
{
	return len;
}

WORD IPv4::GetId() const
{
	return id;
}

WORD IPv4::GetFlags() const
{
	return flags;
}

WORD IPv4::GetFragOff() const
{
	return fragOff;
}

BYTE IPv4::GetTTL() const
{
	return ttl;
}

BYTE IPv4::GetProtocol() const
{
	return protocol;
}

CString IPv4::GetProtocolString() const
{
	CString ret;
	switch(protocol)
	{
	case IP_PROTOCOL_ICMP:
		ret = "ICMP";
		break;
	case IP_PROTOCOL_TCP:
		ret = "TCP";
		break;
	case IP_PROTOCOL_UDP:
		ret = "UDP";
		break;
	default:	
		ret.Format("%4x", protocol);	
		break;
	}
	return ret;
}

WORD IPv4::GetHeadChksum() const
{
	return this->hdrChksum;
}

BYTE IPv4::GetOptions() const
{
	return options;
}

CString IPv4::GetSrc() const
{
	return saddr;
}

CString IPv4::GetDst() const
{
	return daddr;
}

TransmissionPackage * IPv4::GetTrans() const
{
	return trans;
}

IMPLEMENT_DYNCREATE(ARP, ProtocolBase)
ARP::ARP(WORD hwType, WORD protType, BYTE hwAddrLen, BYTE protAddrLen, WORD opcode, CString macsaddr, CString macdaddr, CString saddr, CString daddr)
{
	this->hwType = hwType;
	this->protType = protType;
	this->hwAddrLen = hwAddrLen;
	this->protAddrLen = protAddrLen;
	this->opcode = opcode;
	this->macsaddr = macsaddr;
	this->macdaddr = macdaddr;
	this->saddr = saddr;
	this->daddr = daddr;
}


WORD ARP::GetHWType() const 
{
	return hwType;
}

WORD ARP::GetProtType() const
{
	return protType;
}

BYTE ARP::GetHWAddrLen() const	
{
	return hwAddrLen;
}

BYTE ARP::GetProtAddrLen() const	
{
	return protAddrLen;
}

WORD ARP::GetOpcode() const 
{
	return opcode;
}

CString ARP::GetSrc() const
{
	return saddr;
}

CString ARP::GetDst() const
{
	return daddr;
}

CString ARP::GetMacSrc() const
{
	return macsaddr;
}

CString ARP::GetMacDst() const
{
	return macdaddr;
}
IMPLEMENT_DYNCREATE(TransmissionPackage, CObject)

TransmissionPackage::TransmissionPackage(BYTE *data, WORD datalen)
{
	this->data = data;
	this->datalen = datalen;
}

TransmissionPackage::~TransmissionPackage()
{
	if (data != NULL)
	{
		delete data;
	}
}

BYTE* TransmissionPackage::GetData(WORD &len) const
{
	len = datalen;
	return data;
}

WORD TransmissionPackage::GetDataLen() const
{
	return datalen;
}

IMPLEMENT_DYNCREATE(UDP, TransmissionPackage)
UDP::UDP(WORD sport, WORD dport, WORD len, WORD chksum, BYTE *data, WORD datalen) : TransmissionPackage(data, datalen)
{
	this->sport = sport;
	this->dport = dport;
	this->len = len;
	this->chksum = chksum;
}

UDP::~UDP()
{
	
}

WORD UDP::GetSport() const
{
	return sport;
}

WORD UDP::GetDport()  const
{
	return dport;
}

WORD UDP::GetLen() const
{
	return len;
}

WORD UDP::GetChksum() const
{
	return chksum;
}

IMPLEMENT_DYNCREATE(TCP, TransmissionPackage)
TCP::TCP(WORD sport, WORD dport, DWORD seqnum, DWORD acknum, WORD hlen, BYTE flags, WORD window, WORD chksum, WORD urgptr, BYTE *data, WORD datalen) : TransmissionPackage(data, datalen)
{
	this->sport = sport;
	this->dport = dport;
	this->seqnum = seqnum;
	this->acknum = acknum;
	this->hlen = hlen;
	this->flags = flags;
	this->window = window;
	this->chksum = chksum;
	this->urgptr = urgptr;
}

TCP::~TCP()
{
}

WORD TCP::GetSport() const
{
	return sport;
}

WORD TCP::GetDport() const
{
	return dport;
}

DWORD TCP::GetSeqNum() const
{
	return seqnum;
}

DWORD TCP::GetAckNum() const
{
	return acknum;
}

WORD TCP::GetHLen() const
{
	return hlen;
}

BYTE TCP::GetFlags() const
{
	return flags;
}

WORD TCP::GetWindowSize() const
{
	return window;
}

WORD TCP::GetChksum() const
{
	return chksum;
}

WORD TCP::GetUrgPtr() const
{
	return urgptr;
}

CString TCP::GetFlagsString() const
{
	CString ret = "";
	if (flags & 0x08) 
		ret.Append("PSH ");
	if (flags & 0x10) 
		ret.Append("ACK ");
	if (flags & 0x02) 
		ret.Append("SYN ");
	if (flags & 0x20) 
		ret.Append("URG ");
	if (flags & 0x01) 
		ret.Append("FIN ");
	if (flags & 0x04) 
		ret.Append("RST ");

	return ret;
}

CString TCP::GetSimpleProtocolString() const
{
	CString ret = "²»Ö§³Ö";
	if (sport == 80 || dport == 80)
		ret = "http";
	else if (sport == 21 || dport == 21)
		ret = "ftp";
	else if (sport == 23 || dport == 23)
		ret = "telnet";
	else if (sport == 25 || dport == 25)
		ret = "smtp";
	else if (sport == 110 || dport == 110)
		ret = "pop3";

	return ret;
}

IMPLEMENT_DYNCREATE(PPPoE, ProtocolBase)
PPPoE::PPPoE(BYTE version, BYTE type, BYTE code, WORD sessionID, WORD len, WORD ppp_type, ProtocolBase *next)
{
	this->version = version;
	this->type = type;
	this->code = code;
	this->sessionID = sessionID;
	this->len = len;
	this->next = next;
	this->ppp_type = ppp_type;
}

BYTE PPPoE::GetVersion() const
{
	return version;
}

BYTE PPPoE::GetType() const
{
	return type;
}

BYTE PPPoE::GetCode() const
{
	return code;
}

WORD PPPoE::GetSessionID() const
{
	return sessionID;
}

WORD PPPoE::GetLen() const
{
	return len;
}

void PPPoE::SetNext(ProtocolBase *next)
{
	this->next = next;
}

ProtocolBase *PPPoE::GetNext() const
{
	return next;
}

CString PPPoE::GetTypeString() const
{
	CString ret = "";
	return ret;
}

WORD PPPoE::GetPPPType() const
{
	return ppp_type;
}

CString PPPoE::GetPPPTypeString() const
{
	CString ret;

	switch(ppp_type)
	{
	case PPP_LCP:
		ret = "LCP";
		break;
	case PPP_PAP:
		ret = "PAP";
		break;
	case PPP_CHAP:
		ret = "CHAP";
		break;
	case PPP_IPCP:
		ret = "IPCP";
		break;
	case PPP_IP:
		ret = "IP";
		break;
	default:
		ret.Format("%4x", ppp_type);
		break;
	}
	return ret;
}