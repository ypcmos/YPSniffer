
// YPSnifferDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "protocol.hpp"
#include "Queue.hpp"
// CYPSnifferDlg �Ի���
class CYPSnifferDlg : public CDialogEx
{
// ����
public:
	CYPSnifferDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_YPSNIFFER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

private:
	vector<pcap_if_t*> netCards;
	pcap_t * adhandle;
	HANDLE writeThread, readThread;
public:
	static Queue<Frame*> datas;
	static list<Frame*> sdatas;
	static BOOL stop;
private:
	pcap_if_t* GetNetCard(int i) const;
	void FreeNetCards();
	void FreeNetCard();
	int TurnButton();
	int GetButtonState() const;
	static Frame * GetFrameFromList(int index);
	static void ClearList();
	void ShowTree(Frame * frame);
	void ShowIPv4InTree(const HTREEITEM &item, PVOID param);
	void ShowIPv6InTree(const HTREEITEM &item, PVOID param);
	void ShowARPInTree(const HTREEITEM &item, PVOID param);
	void ShowUDPInTree(const HTREEITEM &item, PVOID param);
	void ShowTCPInTree(const HTREEITEM &item, PVOID param);
	void ShowPPPoEInTree(const HTREEITEM &item, PVOID param);
	void ShowContext(BYTE*data, int len);
	void ShowContext(Frame * frame);
	void Collect();
	void SetMenuUseless(BOOL sign = TRUE);
	CString GetHttpRequest(const Frame * frame, BYTE s = 1);
// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_NetCards;
	CComboBox m_Rules;
	CEdit m_NetCardInfo;
	afx_msg void OnCbnSelchangeCombo1();
	CListCtrl m_EthList;
	CButton m_IsChaos;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedCancel();
	CEdit m_Context;
	CTreeCtrl m_Tree;
	afx_msg void OnNMDblclkList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnGetHttpRequest();
	afx_msg void OnGetCookies();
	afx_msg void OnClear();
	afx_msg void OnAbout();
};
