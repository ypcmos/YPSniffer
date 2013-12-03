
// YPSnifferDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "protocol.hpp"
#include "Queue.hpp"
// CYPSnifferDlg 对话框
class CYPSnifferDlg : public CDialogEx
{
// 构造
public:
	CYPSnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_YPSNIFFER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

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
// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
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
