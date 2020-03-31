#include "EnglishText.h"
#include <iostream>

void EnglishText::PrintCharByFreq()
{
	for (std::vector<char>::iterator itvcc = alphaByFreq.begin(); itvcc != alphaByFreq.end(); ++itvcc)
	{
		std::cout << *itvcc;
	}
	std::cout << std::endl;
}

// construct a vector containing the first N words of size M
std::vector<std::string> EnglishText::GetFirstNofWordSize(size_t count, size_t wdLen)
{
	MessageBase::VectorWords::const_iterator t = vvWordsByFreq[wdLen].begin();
	MessageBase::VectorWords::const_iterator tx = vvWordsByFreq[wdLen].begin() + 2;
	MessageBase::VectorWords res(t, tx);
	return res;
}


MessageBase::VectorWords EnglishText::GetWordVectorOfLenN(size_t count, size_t wordLen)
{
	MessageBase::VectorWords::const_iterator t = vvWordsByFreq[wordLen].begin();
	MessageBase::VectorWords::const_iterator tx = vvWordsByFreq[wordLen].begin() + count;
	MessageBase::VectorWords res(t, tx);
	return res;

}
