#pragma once
#include <queue>
using namespace std;
#include <Windows.h>

template<class T>
class Queue
{
public:
	Queue();
	~Queue();
	void push(T d);
	void pop();
	T front();
	bool empty();

private:
	queue<T> q;
	HANDLE mutex;
};

template<class T>
Queue<T>::Queue()
{
	mutex = CreateMutex(0, FALSE, 0);
}

template<class T>
Queue<T>::~Queue()
{
	CloseHandle(mutex);
}

template<class T>
void Queue<T>::push(T d)
{
	WaitForSingleObject(mutex, INFINITE);
	q.push(d);
	ReleaseMutex(mutex);
}

template<class T>
void Queue<T>::pop()
{
	WaitForSingleObject(mutex, INFINITE);
	q.pop();
	ReleaseMutex(mutex);
}

template<class T>
T Queue<T>::front()
{
	WaitForSingleObject(mutex, INFINITE);
	T ret = q.front();
	ReleaseMutex(mutex);
	return ret;
}

template<class T>
bool Queue<T>::empty()
{
	WaitForSingleObject(mutex, INFINITE);
	bool ret = q.empty();
	ReleaseMutex(mutex);
	return ret;
}
