#pragma once
#include <iostream>

class CharPtFreqCtFreq
{
public:
	char key;
	double ptFreq;
	double ctFreq;

	CharPtFreqCtFreq(char k, double ptf, double ctf)
		: key(k), ptFreq(ptf), ctFreq(ctf)
	{
	}

	void Print()
	{
		std::cout << "[" << key << ", " << ptFreq << ", " << ctFreq << "]";
	}
};

