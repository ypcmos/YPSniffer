
// YPSnifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "YPSniffer.h"

#include "YPSnifferDlg.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

Queue<Frame*> CYPSnifferDlg::datas;
list<Frame*> CYPSnifferDlg::sdatas;
BOOL CYPSnifferDlg::stop = FALSE;
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CYPSnifferDlg �Ի���




CYPSnifferDlg::CYPSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CYPSnifferDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	adhandle = NULL;
}

void CYPSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_NetCards);
	DDX_Control(pDX, IDC_COMBO2, m_Rules);
	DDX_Control(pDX, IDC_EDIT1, m_NetCardInfo);
	DDX_Control(pDX, IDC_LIST1, m_EthList);
	DDX_Control(pDX, IDC_CHECK1, m_IsChaos);
	DDX_Control(pDX, IDC_EDIT2, m_Context);
	DDX_Control(pDX, IDC_TREE1, m_Tree);
}

BEGIN_MESSAGE_MAP(CYPSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CYPSnifferDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON1, &CYPSnifferDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDCANCEL, &CYPSnifferDlg::OnBnClickedCancel)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST1, &CYPSnifferDlg::OnNMDblclkList1)
	ON_COMMAND(ID_HTTPREQUEST, &CYPSnifferDlg::OnGetHttpRequest)
	ON_COMMAND(ID_COOKIES, &CYPSnifferDlg::OnGetCookies)
	ON_COMMAND(ID_CLEAR, &CYPSnifferDlg::OnClear)
	ON_COMMAND(ID_ABOUT, &CYPSnifferDlg::OnAbout)
END_MESSAGE_MAP()

pcap_if_t* CYPSnifferDlg::GetNetCard(int i) const
{
	if (i < netCards.size())
	{
		return netCards[i];
	}
	
	return NULL;
}

void CYPSnifferDlg::FreeNetCard()
{
	if (adhandle != NULL)
	{
		pcap_breakloop(adhandle);
		pcap_close(adhandle);
		adhandle = NULL;
	}
}
void CYPSnifferDlg::FreeNetCards()
{
	pcap_if_t * all = GetNetCard(0);

	if (all != NULL)
	{
		pcap_freealldevs(all);
	}
	netCards.clear();
}

Frame * CYPSnifferDlg::GetFrameFromList(int index)
{
	list<Frame*>::iterator it;

	int i = 0;
	for (it = sdatas.begin(); it != sdatas.end(); it++, i++)
	{
		if (i == index)
		{
			return *it;
		}	
	}
	return NULL;
}

void CYPSnifferDlg::ClearList()
{
	list<Frame*>::iterator it;

	for (it = sdatas.begin(); it != sdatas.end(); it++)
	{	
		delete *it;	
	}
	sdatas.clear();
}
// CYPSnifferDlg ��Ϣ�������

BOOL CYPSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	pcap_if_t * alldevs, *d; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	/* ��ȡ�豸�б� */ 
	if (pcap_findalldevs(&alldevs, errbuf) == -1) 
	{ 
		MessageBox("Ӧ�ó��������ȷ���Ѱ�װWinpcap.");
		exit(1); 
	} 
	/* �����б� */ 
	m_NetCards.AddString("��ѡ������");
	for(d=alldevs; d; d=d->next) 
	{ 
		
		if (d->description) 
		{
			m_NetCards.AddString(d->description);
		}
		else
		{
			m_NetCards.AddString("������");
		}
		netCards.push_back(d);
	} 

	m_Rules.AddString("ȫ��");
	m_Rules.AddString("ip");
	m_Rules.AddString("ip6");
	m_Rules.AddString("ip or ip6");
	m_Rules.AddString("tcp");
	m_Rules.AddString("udp");
	m_Rules.AddString("pppoes");
	m_Rules.AddString("pppoes and ip");
	m_NetCards.SetCurSel(0);
	m_Rules.SetCurSel(0);

	m_EthList.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
	m_EthList.InsertColumn(0, _T("���"), 3, 50);                        //1��ʾ�ң���ʾ�У���ʾ��
	m_EthList.InsertColumn(1, _T("ʱ��"), 3, 80);
	m_EthList.InsertColumn(2, _T("����"), 3, 50);
	m_EthList.InsertColumn(3, _T("ԴMAC��ַ"), 3, 140);
	m_EthList.InsertColumn(4, _T("Ŀ��MAC��ַ"), 3, 140);
	m_EthList.InsertColumn(5, _T("Э��"), 3, 70);

	m_Tree.SetBkColor (RGB(220,200,220));//������ɫ
	DWORD dwStyle=GetWindowLong(m_Tree.m_hWnd ,GWL_STYLE);//���������Ϣ
	dwStyle|=TVS_HASBUTTONS|TVS_HASLINES|TVS_LINESATROOT;//���÷��
	::SetWindowLong (m_Tree.m_hWnd ,GWL_STYLE,dwStyle);
	
	SetMenuUseless();
	HFONT hFont = (HFONT)::GetStockObject(SYSTEM_FIXED_FONT);
    CFont *pFont = CFont::FromHandle(hFont);
	m_Context.SetFont(pFont);
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CYPSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CYPSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CYPSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CYPSnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int index = m_NetCards.GetCurSel();
	if (index > 0)
	{
		pcap_if_t* device = GetNetCard(index - 1);
		CString text = "";
		text += device->name;
		text += "\r\n";
		CString temp;
		for(pcap_addr * a = device->addresses; a; a = a->next) 
		{ 
			switch(a->addr->sa_family) 
			{ 
			case AF_INET: 
				temp.Format("Address Family Name: AF_INET(IPv4)\r\n"); 
				text += temp;
				if (a->addr) 
				{
					temp.Format("Address: %s\r\n", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
					text += temp;
				}
				if (a->netmask) 
				{
					temp.Format("Netmask: %s\r\n", inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
					text += temp;
				}
				if (a->broadaddr)
				{
					temp.Format("Broadcast Address: %s\r\n", inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr)); 
					text += temp;
				}
				if (a->dstaddr) 
				{
					temp.Format("Destination Address: %s\r\n", inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr)); 
					text += temp;
				}
				
				break; 
			case AF_INET6: 
				temp.Format("Address Family Name: AF_INET6(IPv6)\r\n"); 
				text += temp;
				char ip[100];
				if (a->addr) 
				{
					inet_ntop(PF_INET6, &((struct sockaddr_in6 *)a->addr)->sin6_addr, ip, sizeof(ip));
					temp.Format("Address: %s\r\n", ip);
					text += temp;
				}
				break; 
			default: 
				temp.Format("Address Family Name: Unknown\r\n"); 
				text += temp;
				break; 
			} 
		} 
		m_NetCardInfo.SetWindowText(text);
	}else{
		m_NetCardInfo.SetWindowText("");
	}
}

int CYPSnifferDlg::TurnButton()
{
	CString text;
	GetDlgItemText(IDC_BUTTON1, text);

	if (text == "��ʼ��̽")
	{
		SetDlgItemText(IDC_BUTTON1, "ֹͣ");
		SetMenuUseless();
		return 1;
	} else {
		SetDlgItemText(IDC_BUTTON1, "��ʼ��̽");
		SetMenuUseless(FALSE);
		return 0;
	}
}

int CYPSnifferDlg::GetButtonState() const
{
	CString text;
	GetDlgItemText(IDC_BUTTON1, text);

	if (text == "��ʼ��̽")
	{
		return 1;
	} else {
		return 0;
	}
}

UDP *DecodeUDPPackage(const BYTE * data)
{
	LPUDPHeader uhdr = (LPUDPHeader)data;
	WORD sport = ntohs(uhdr->SrcPort);
	WORD dport = ntohs(uhdr->DstPort);
	WORD len = ntohs(uhdr->Len);
	WORD chksum = ntohs(uhdr->Chksum);
	BYTE * udpdata = NULL;
	int uhdrlen = sizeof(UDPHeader);
	int datalen = (int)len - uhdrlen;

	if (datalen > 0)
	{
		udpdata = new BYTE[datalen];
		memcpy(udpdata, data + uhdrlen, datalen);
	}
	return new UDP(sport, dport, len, chksum, udpdata, datalen);
}

TCP *DecodeTCPPackage(const BYTE * data, int iphlen, int len)
{
	LPTCPHeader thdr = (LPTCPHeader)data;
	WORD sport = ntohs(thdr->SrcPort);
	WORD dport = ntohs(thdr->DstPort);
	WORD chksum = ntohs(thdr->Chksum);
	DWORD seqnum = ntohl(thdr->SeqNum);
	DWORD acknum = ntohl(thdr->AckNum); 
	WORD hlen = (thdr->DataOff >> 4 & 0xf) * 4;
	BYTE flags = thdr->Flags;
	WORD window = ntohs(thdr->Window);
	WORD urgptr = ntohs(thdr->UrgPtr);
	BYTE * udpdata = NULL;
	int datalen = len - hlen - iphlen;

	if (datalen > 0)
	{
		udpdata = new BYTE[datalen];
		memcpy(udpdata, data + hlen, datalen);
	}
	return new TCP(sport, dport, seqnum, acknum, hlen, flags, window, chksum, urgptr, udpdata, datalen);
}

IPv4* DecodeIPPackage(const BYTE * data)
{
	LPIPHeader liphdr = (LPIPHeader)data;
	DWORD hdrLen = (liphdr->HdrLen & 0x0f) * 4;
	BYTE* left = (BYTE*)data + hdrLen;
	WORD offset = ntohs(liphdr->FragOff);
	WORD flags = offset >> 13;
	BYTE version = liphdr->Version >> 4 & 0xf;
	BYTE type = liphdr->ServiceType;
	WORD len = ntohs(liphdr->TotalLen);
	WORD id = ntohs(liphdr->ID);
	WORD fragOff = (offset & 0x1fff) * 8;
	BYTE ttl = liphdr->TimeToLive;
	BYTE protocol = liphdr->Protocol;
	WORD hdrChksum = ntohs(liphdr->HdrChksum);
	CString saddr = inet_ntoa(*(in_addr*)&liphdr->SrcAddr);
	CString daddr = inet_ntoa(*(in_addr*)&liphdr->DstAddr);
	BYTE options = liphdr->Options;
	IPv4 *ipv4 = new IPv4(version, hdrLen, type, len,id, flags, fragOff, ttl, protocol, hdrChksum, options, saddr, daddr);
	switch(protocol)
	{
	case IP_PROTOCOL_TCP: 
		ipv4->SetTrans(DecodeTCPPackage(left, ipv4->GetHeadLen(), ipv4->GetLen()));
		break;
	case IP_PROTOCOL_UDP: 
		ipv4->SetTrans(DecodeUDPPackage(left));
		break;
	case IP_PROTOCOL_ICMP: 
		break;
	default: 
		break;
	}
	return ipv4;
}

IPv6* DecodeIPv6Package(const BYTE * data)
{
	LPIPv6Header liphdr = (LPIPv6Header)data;
	BYTE* left = (BYTE*)data + sizeof(IPv6Header);
	
	BYTE version = ntohl(liphdr->version) >> 28;
	BYTE flowid = ntohl(liphdr->flowid) >> 20 & 0xff;
	DWORD flowtype = ntohl(liphdr->flowtype) & 0xfffff;
	WORD plen = ntohs(liphdr->plen);
	BYTE hlim = liphdr->hlim;
	BYTE nh = liphdr->nh;
	char ip[100];
	inet_ntop(PF_INET6, &liphdr->saddr, ip, sizeof(ip));
	CString saddr = ip;
	inet_ntop(PF_INET6, &liphdr->daddr, ip, sizeof(ip));
	CString daddr = ip;
	IPv6 *ipv6 = new IPv6(version, flowtype, flowid, plen, nh, hlim, saddr, daddr);
	switch(nh)
	{
	case IP_PROTOCOL_TCP: 
		ipv6->SetTrans(DecodeTCPPackage(left, 0, ipv6->GetLen()));
		break;
	case IP_PROTOCOL_UDP: 
		ipv6->SetTrans(DecodeUDPPackage(left));
		break;
	case IP_PROTOCOL_ICMPV6: 
		break;
	default: 
		break;
	}
	return ipv6;
}

ARP* DecodeARPPackage(const BYTE * data)
{
	LPARPFrame arpframe = (LPARPFrame)data;
	BYTE hwAddrLen = arpframe->HWAddrLen;
	WORD hwType = ntohs(arpframe->HWType);
	WORD protType = ntohs(arpframe->ProtType);
	BYTE protAddrLen = arpframe->ProtAddrLen;
	WORD opcode = arpframe->Opcode;
	CString macsaddr, macdaddr, saddr, daddr;
	macsaddr.Format("%2x:%2x:%2x:%2x:%2x:%2x", arpframe->SendHWAddr[0], arpframe->SendHWAddr[1], arpframe->SendHWAddr[2], arpframe->SendHWAddr[3], arpframe->SendHWAddr[4], arpframe->SendHWAddr[5]);
	macdaddr.Format("%2x:%2x:%2x:%2x:%2x:%2x", arpframe->TargHWAddr[0], arpframe->TargHWAddr[1], arpframe->TargHWAddr[2], arpframe->TargHWAddr[3], arpframe->TargHWAddr[4], arpframe->TargHWAddr[5]);
	saddr = inet_ntoa(*(in_addr*)arpframe->SendProtAddr);
	daddr = inet_ntoa(*(in_addr*)arpframe->TargProtAddr);
	ARP * arp = new ARP(hwType, protType, hwAddrLen, protAddrLen, opcode, macsaddr, macdaddr, saddr, daddr);
	return arp;
}

PPPoE* DecodePPPoEPackage(const BYTE * data)
{
	LPPPPoEHeader phdr = (LPPPPoEHeader)data;
	BYTE version = phdr->Version >> 4 & 0xf;
	BYTE type = phdr->Type & 0xf;
	BYTE code = phdr->Code;
	WORD sessionID = ntohs(phdr->SessionID);
	WORD len = ntohs(phdr->Len);
	WORD ppp_type = ntohs(phdr->ppp_type);
	PPPoE * pppoe = new PPPoE(version, type, code, sessionID, len, ppp_type);

	switch(ppp_type)
	{
	case PPP_IP:
		pppoe->SetNext(DecodeIPPackage((BYTE*)data + sizeof(PPPoEHeader)));
		break;
	//no default
	}
	return pppoe;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) 
{ 
	struct tm *ltime;
	char timestr[16]; 
	/* ת��ʱ���Ϊ�����Ķ��ĸ�ʽ */ 
	
	__int64 sec = header->ts.tv_sec;
	ltime = localtime((time_t*)&sec); 
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime); 
	CString src, dst;
	
	LPETHHeader lethhdr = (LPETHHeader)pkt_data;
	src.Format("%2x:%2x:%2x:%2x:%2x:%2x", lethhdr->Src[0], lethhdr->Src[1], lethhdr->Src[2], lethhdr->Src[3], lethhdr->Src[4], lethhdr->Src[5]);
	dst.Format("%2x:%2x:%2x:%2x:%2x:%2x", lethhdr->Dst[0], lethhdr->Dst[1], lethhdr->Dst[2], lethhdr->Dst[3], lethhdr->Dst[4], lethhdr->Dst[5]);
	WORD type = ntohs(lethhdr->Type);
	EthHeader *eth = new EthHeader(src, dst, type);
	Frame *frame = new Frame(eth, timestr, header->len);
	CYPSnifferDlg::datas.push(frame);
	
	switch(type)
	{
	case ETH_PROTOCOL_IP:
		eth->SetProtocol(DecodeIPPackage((BYTE*)pkt_data + sizeof(ETHHeader)));
		break;
	case ETH_PROTOCOL_IPV6:	   
		eth->SetProtocol(DecodeIPv6Package((BYTE*)pkt_data + sizeof(ETHHeader)));
		break;
	case ETH_PROTOCOL_RARP:            
		break;
	case ETH_PROTOCOL_ARP: 
		eth->SetProtocol(DecodeARPPackage((BYTE*)pkt_data + sizeof(ETHHeader)));
		break;
	case ETH_PROTOCOL_PPP_SESSION:
		eth->SetProtocol(DecodePPPoEPackage((BYTE*)pkt_data + sizeof(ETHHeader)));
		break;
	default:
		break;
	}
}

UINT WINAPI SnifferThread(LPVOID lpParameter)
{
	pcap_t* adhandle = (pcap_t*)lpParameter;
	pcap_loop(adhandle, 0, packet_handler, NULL); 
	AfxMessageBox("��ֹͣ��̽");
	_endthreadex(0);
	return 0;
}

UINT WINAPI ReadThread(LPVOID lpParameter)
{
	CListCtrl* m_list = (CListCtrl*)lpParameter;
	while(!CYPSnifferDlg::stop)
	{
		if (CYPSnifferDlg::datas.empty())
		{
			Sleep(10);
			continue;
		}
		Frame * frame = CYPSnifferDlg::datas.front();
		int index = CYPSnifferDlg::sdatas.size();
		CYPSnifferDlg::sdatas.push_back(frame);
		CYPSnifferDlg::datas.pop();
		CString temp;
		temp.Format("%d", index);
		int ex = m_list->GetItemCount();
		m_list->SetRedraw(FALSE);
		int nRow = m_list->InsertItem(ex, temp);
		m_list->SetItemText(nRow, 1, frame->GetTime());
		temp.Format("%d", frame->GetLen());
		m_list->SetItemText(nRow, 2, temp);
		EthHeader *eth = frame->GetEthHeader();
		m_list->SetItemText(nRow, 3, eth->GetSource());
		m_list->SetItemText(nRow, 4, eth->GetDestnation());
		m_list->SetItemText(nRow, 5, eth->GetTypeString());
		m_list->SetRedraw();
		m_list->EnsureVisible(nRow, TRUE);	
	}
	_endthreadex(0);
	return 0;
}

void CYPSnifferDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (GetButtonState() == 0)
	{
		Collect();
		TurnButton();
		return;
	}
	stop = FALSE;
	int index = m_NetCards.GetCurSel();
	if (index > 0)
	{
		pcap_if_t* device = GetNetCard(index - 1);
		
		char errbuf[PCAP_ERRBUF_SIZE]; 
		int promisc = 0;
		if (m_IsChaos.GetCheck() == BST_CHECKED)
		{
			promisc = 1;
		}

		if ((adhandle= pcap_open_live(device->name, 65536, promisc, 1000, errbuf)) == NULL) 
		{ 
			MessageBox(errbuf); 
			return; 
		} 

		if (pcap_datalink(adhandle) != DLT_EN10MB) 
		{ 
			MessageBox("����ֻ�ܹ�������̫����.");
			return; 
		}

		index = m_Rules.GetCurSel();
		CString rule;
		if (index > 0)
		{
			m_Rules.GetLBText(index, rule);
			char* packet_filter = rule.GetBuffer(0); 
			struct bpf_program fcode; 
			u_int netmask;
			if(device->addresses != NULL)
				netmask=((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr; 
			else 
				netmask=0xffffff; 
 
			if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 ) 
			{ 
				MessageBox("�޷�����������.");
				return; 
			} 

			if (pcap_setfilter(adhandle, &fcode)<0) 
			{ 
				MessageBox("�޷�����������.");
				return; 
			} 
		}
		UINT id1, id2;
		writeThread = (HANDLE)_beginthreadex(NULL, 0, SnifferThread, adhandle, 0, &id1);
		CloseHandle(writeThread);
		readThread = (HANDLE)_beginthreadex(NULL, 0, ReadThread, &m_EthList, 0, &id2);
		CloseHandle(readThread);
		TurnButton();
	}
	else
	{
		MessageBox("����ѡ��һ������.");
	}
}

void CYPSnifferDlg::Collect()
{
	CYPSnifferDlg::stop = TRUE;

	while (!datas.empty()) 
	{
		delete datas.front();
        datas.pop();
    }
	FreeNetCard();
}

void CYPSnifferDlg::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	Collect();
	FreeNetCards();
	ClearList();
	CDialogEx::OnCancel();
}


void CYPSnifferDlg::OnNMDblclkList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int cur = m_EthList.GetSelectionMark();

	if (cur != -1)
	{
		CString text = m_EthList.GetItemText(cur, 0);
		Frame * frame = GetFrameFromList(atoi(text));
		ShowTree(frame);
		ShowContext(frame);
	}
	*pResult = 0;
}

void CYPSnifferDlg::ShowUDPInTree(const HTREEITEM &udpitem, PVOID param)
{
	UDP * udp = (UDP*)param;
	CString text;
	text.Format("���Ͷ˿�:%d[d]", udp->GetSport());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("���ն˿�:%d[d]", udp->GetDport());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("���ݱ�����:%d[d]", udp->GetLen());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("У����:%d[d]", udp->GetChksum());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
}

void CYPSnifferDlg::ShowTCPInTree(const HTREEITEM &udpitem, PVOID param)
{
	TCP * tcp = (TCP*)param;
	CString text;
	text.Format("���Ͷ˿�:%d[d]", tcp->GetSport());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("���ն˿�:%d[d]", tcp->GetDport());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("ͷ��:%d[d]", tcp->GetHLen());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("�ϲ�Э��:%s", tcp->GetSimpleProtocolString());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("��־:%x(%s)", tcp->GetFlags(), tcp->GetFlagsString());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("ACK:%x", tcp->GetAckNum());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("SEQ:%x", tcp->GetSeqNum());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("���ڴ�С:%d[d]", tcp->GetWindowSize());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("У����:%d[d]", tcp->GetChksum());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
	text.Format("����ָ��:%x", tcp->GetUrgPtr());
	m_Tree.InsertItem(text , udpitem, TVI_LAST);
}

void CYPSnifferDlg::ShowIPv4InTree(const HTREEITEM &item, PVOID param)
{
	IPv4 * ipv4 = (IPv4 *)param;
	CString text;
	text.Format("�汾:%2x", ipv4->GetVersion());
	m_Tree.InsertItem(text , item, TVI_LAST);
	text.Format("ID:%4x", ipv4->GetId());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("��������:%2x", ipv4->GetServiceType());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("ͷ��:%d[d]", ipv4->GetHeadLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("ͷ��У���:%4x", ipv4->GetHeadChksum());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("��־:%4x", ipv4->GetFlags());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("ƫ��:%4x", ipv4->GetFragOff());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����:%d[d]", ipv4->GetLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("�ϲ�Э��:%s", ipv4->GetProtocolString());
	HTREEITEM pai = m_Tree.InsertItem(text, item, TVI_LAST);	
	m_Tree.InsertItem("Դ��ַ:" + ipv4->GetSrc(), item, TVI_LAST);
	m_Tree.InsertItem("Ŀ�ĵ�ַ:" + ipv4->GetDst(), item, TVI_LAST);
	text.Format("ѡ��:%2x", ipv4->GetOptions());
	m_Tree.InsertItem(text, item, TVI_LAST);
	TransmissionPackage *pack = ipv4->GetTrans();

	if (pack == NULL)
	{
		return;
	}

	if (pack->IsKindOf(RUNTIME_CLASS(UDP)))
	{
		ShowUDPInTree(pai, pack);
	} else if (pack->IsKindOf(RUNTIME_CLASS(TCP))) {
		ShowTCPInTree(pai, pack);
	}
	m_Tree.Expand(pai, TVE_EXPAND);
}

void CYPSnifferDlg::ShowIPv6InTree(const HTREEITEM &item, PVOID param)
{
	IPv6 * ipv6 = (IPv6 *)param;
	CString text;
	text.Format("�汾:%2x", ipv6->GetVersion());
	m_Tree.InsertItem(text , item, TVI_LAST);
	text.Format("ID:%x", ipv6->GetFlowId());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����:%x", ipv6->GetFlowType());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("������:%d[d]", ipv6->GetJumpLimit());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����:%d[d]", ipv6->GetLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("��һ��ͷ:%s", ipv6->GetNextHeadString());
	HTREEITEM pai = m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("Դ��ַ:%s", ipv6->GetSrc());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("Ŀ���ַ:%s", ipv6->GetDst());
	m_Tree.InsertItem(text, item, TVI_LAST);
	TransmissionPackage *pack = ipv6->GetTrans();

	if (pack == NULL)
	{
		return;
	}

	if (pack->IsKindOf(RUNTIME_CLASS(UDP)))
	{
		ShowUDPInTree(pai, pack);
	} else if (pack->IsKindOf(RUNTIME_CLASS(TCP))) {
		ShowTCPInTree(pai, pack);
	}
	m_Tree.Expand(pai, TVE_EXPAND);
	
}

void CYPSnifferDlg::ShowARPInTree(const HTREEITEM &item, PVOID param)
{
	ARP * arp = (ARP*)param;
	CString text;
	text.Format("Ӳ������:%4x", arp->GetHWType());
	m_Tree.InsertItem(text , item, TVI_LAST);
	text.Format("Э������:%4x", arp->GetProtType());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("Ӳ����ַ����:%2x", arp->GetHWAddrLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("Э���ַ����:%2x", arp->GetProtAddrLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("ARP/RARP:%4x", arp->GetOpcode());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����Ӳ����ַ:%s", arp->GetMacSrc());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����Ӳ����ַ:%s", arp->GetMacDst());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����Э���ַ:%s", arp->GetSrc());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����Э���ַ:%s", arp->GetDst());
	m_Tree.InsertItem(text, item, TVI_LAST);
}

void CYPSnifferDlg::ShowPPPoEInTree(const HTREEITEM &item, PVOID param)
{
	PPPoE * pppoe = (PPPoE*)param;
	CString text;
	text.Format("�汾:%1x", pppoe->GetVersion());
	m_Tree.InsertItem(text , item, TVI_LAST);
	text.Format("����:%1x", pppoe->GetType());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����:%2x", pppoe->GetCode());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("SessionID:%4x", pppoe->GetSessionID());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("����:%d[d]", pppoe->GetLen());
	m_Tree.InsertItem(text, item, TVI_LAST);
	text.Format("PPP����:%s", pppoe->GetPPPTypeString());
	HTREEITEM pie = m_Tree.InsertItem(text, item, TVI_LAST);

	ProtocolBase * pro = pppoe->GetNext();
	if (pro != NULL)
	{
		if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
		{
			ShowIPv4InTree(pie, pro);
		}
		m_Tree.Expand(pie, TVE_EXPAND);
	}
}

void CYPSnifferDlg::ShowTree(Frame * frame)
{
	m_Tree.DeleteAllItems();
	EthHeader *eth = frame->GetEthHeader();
	HTREEITEM root = m_Tree.InsertItem(eth->GetTypeString());
	ProtocolBase *pro = eth->GetProtocol();
	if (pro == NULL)
	{
		m_Tree.InsertItem("��֧�ִ���Э��Ľ���", root, TVI_LAST);
	} else {
		if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
		{
			ShowIPv4InTree(root, pro);
		} else if (pro->IsKindOf(RUNTIME_CLASS(IPv6))) {
			ShowIPv6InTree(root, pro);
		} else if (pro->IsKindOf(RUNTIME_CLASS(ARP))) {
			ShowARPInTree(root, pro);
		} else if (pro->IsKindOf(RUNTIME_CLASS(PPPoE))) {
			ShowPPPoEInTree(root, pro);
		}
	}
	m_Tree.Expand(root, TVE_EXPAND);
}

void CYPSnifferDlg::ShowContext(BYTE*data, int len)
{
	CString context = "";
	int full = len / 16;
	int left = len % 16;

	for (int i = 0; i < full; i++)
	{	
		context.AppendFormat("%04x ", i * 16);
		
		for (int j = 0; j < 16; j++)
		{
			context.AppendFormat("%02x ", data[i * 16 + j]);
		}	
		
		context.AppendFormat("   ");
		for (int j = 0; j < 16; j++)
		{
			context.AppendFormat("%c", isprint(data[i * 16 + j])? data[i * 16 + j]: '.');
		}
		context += "\r\n";	
	}

	if (left > 0)
	{	
		context.AppendFormat("%04x ", full * 16);
		
		for (int j = 0; j < left; j++)
		{
			context.AppendFormat("%02x ", data[full * 16 + j]);
		}	

		for (int j = left; j < 16; j++)
		{
			context.AppendFormat("   ");
		}
		
		context.AppendFormat("   ");
		for (int j = 0; j < left; j++)
		{
			context.AppendFormat("%c", isprint(data[full * 16 + j]) ? data[full * 16 + j] : '.');
		}
		context += "\r\n";	
	}

	m_Context.SetWindowText(context);
}

void CYPSnifferDlg::ShowContext(Frame * frame)
{
	EthHeader *eth = frame->GetEthHeader();

	ProtocolBase *pro = eth->GetProtocol();
	if (pro != NULL)
	{
		TransmissionPackage *pack = NULL;
		if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
		{
			pack = ((IPv4*)pro)->GetTrans();		
		} 
		
		else if (pro->IsKindOf(RUNTIME_CLASS(IPv6)))
		{
			pack = ((IPv6*)pro)->GetTrans();	
		}

		else if (pro->IsKindOf(RUNTIME_CLASS(PPPoE)))
		{
			pro = ((PPPoE*)pro)->GetNext();
			if (pro != NULL)
			{
				if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
				{
					pack = ((IPv4*)pro)->GetTrans();		
				} 
		
				else if (pro->IsKindOf(RUNTIME_CLASS(IPv6)))
				{
					pack = ((IPv6*)pro)->GetTrans();	
				}
			}
		}

		if (pack != NULL)
		{
			WORD len;
			BYTE * data = pack->GetData(len);
			ShowContext(data, len);
		}
	}
}

CString CYPSnifferDlg::GetHttpRequest(const Frame * frame, BYTE s)
{
	EthHeader *eth = frame->GetEthHeader();
	CString ret = "";
	ProtocolBase *pro = eth->GetProtocol();
	if (pro != NULL)
	{
		TransmissionPackage *pack = NULL;
		if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
		{
			pack = ((IPv4*)pro)->GetTrans();		
		} 
		
		else if (pro->IsKindOf(RUNTIME_CLASS(IPv6)))
		{
			pack = ((IPv6*)pro)->GetTrans();	
		}

		else if (pro->IsKindOf(RUNTIME_CLASS(PPPoE)))
		{
			pro = ((PPPoE*)pro)->GetNext();
			if (pro != NULL)
			{
				if (pro->IsKindOf(RUNTIME_CLASS(IPv4)))
				{
					pack = ((IPv4*)pro)->GetTrans();		
				} 
		
				else if (pro->IsKindOf(RUNTIME_CLASS(IPv6)))
				{
					pack = ((IPv6*)pro)->GetTrans();	
				}
			}
		}

		if (pack != NULL && pack->IsKindOf(RUNTIME_CLASS(TCP)))
		{
			TCP *tcp = (TCP*)pack;

			if (tcp->GetSport() == 80 || tcp->GetDport() == 80)
			{
				WORD len;
				BYTE * data = pack->GetData(len);
				if (len > 10)
				{
					for (int i = 0; i < len; i++)
					{
						ret.AppendFormat("%c", data[i]);
					}

					CString temp = ret.Left(3);

					if (!temp.CompareNoCase("GET"))
					{
					}
					else
					{
						temp = ret.Left(4);
						if (!temp.CompareNoCase("POST"))
						{
						} else {
							return "";
						}
					}
					if (s == 1)
					{
						return ret;
					} else if (s == 2) {
						if (ret.Find("ookie") != -1)
						{
							return ret;
						} else {
							return "";
						}
					}
				}

			}
		}
	}
	return ret;
}

void CYPSnifferDlg::OnGetHttpRequest()
{
	// TODO: �ڴ���������������
	list<Frame*>::iterator it;
	CString text = "";
	for (it = sdatas.begin(); it != sdatas.end(); it++)
	{	
		CString temp = GetHttpRequest(*it);
		
		if (temp != "")
		{
			CString index;
			index.Format("�б���:%d\r\n", distance(sdatas.begin(), it));
			text += index + temp + "\r\n--------------------\r\n";
		}
	}
	char filename[] = "http-request.dat";
	fstream fp;
	fp.open(filename, ios::out);
	fp.write(text.GetBuffer(0), text.GetLength());
	fp.flush();
	fp.close();
	ShellExecute(this->m_hWnd, _T("open"), _T("notepad.exe"), filename, NULL, SW_SHOW);
}


void CYPSnifferDlg::OnGetCookies()
{
	// TODO: �ڴ���������������
	list<Frame*>::iterator it;
	CString text = "";
	for (it = sdatas.begin(); it != sdatas.end(); it++)
	{	
		CString temp = GetHttpRequest(*it, 2);
		
		if (temp != "")
		{
			CString index;
			index.Format("�б���:%d\r\n", distance(sdatas.begin(), it));
			text += index + temp + "\r\n--------------------\r\n";
		}
	}
	char filename[] = "cookies.dat";
	fstream fp;
	fp.open(filename, ios::out);
	fp.write(text.GetBuffer(0), text.GetLength());
	fp.flush();
	fp.close();
	ShellExecute(this->m_hWnd, _T("open"), _T("notepad.exe"), filename, NULL, SW_SHOW);
}


void CYPSnifferDlg::OnClear()
{
	// TODO: �ڴ���������������
	ClearList();
	m_Tree.DeleteAllItems();
	m_Context.SetWindowText("");
	m_EthList.DeleteAllItems();
}


void CYPSnifferDlg::OnAbout()
{
	// TODO: �ڴ���������������
	CAboutDlg dlg;
	dlg.DoModal();
}

void CYPSnifferDlg::SetMenuUseless(BOOL sign)
{
	CMenu *pmenu = GetMenu();
	DWORD state = sign ? MF_GRAYED : MF_ENABLED;
	pmenu->EnableMenuItem(ID_HTTPREQUEST, state); 
	pmenu->EnableMenuItem(ID_COOKIES, state);
	pmenu->EnableMenuItem(ID_CLEAR, state);
}