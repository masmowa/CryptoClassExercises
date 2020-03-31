#pragma once
#include <iostream>

class CharFreqNode
{
public:
	char key;
	double freq;

	CharFreqNode(char k, double v)
		: key(k), freq(v)
	{}
	friend bool operator< (const CharFreqNode& lhs, const CharFreqNode& rhs);
	friend bool operator> (const CharFreqNode& lhs, const CharFreqNode& rhs);
	friend bool operator== (const CharFreqNode& lhs, const CharFreqNode& rhs);

	void Print()
	{
		std::cout << "[" << key << ", " << freq << "]";
	}
};

inline bool operator<(const CharFreqNode& lhs, const CharFreqNode& rhs)
{
	return (lhs.freq < rhs.freq);
}
inline bool operator>(const CharFreqNode& lhs, const CharFreqNode& rhs)
{
	return (lhs.freq > rhs.freq);
}
inline bool operator==(const CharFreqNode& lhs, const CharFreqNode& rhs)
{
	return (lhs.freq == rhs.freq);
}
