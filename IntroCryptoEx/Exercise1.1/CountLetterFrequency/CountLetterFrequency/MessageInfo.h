#pragma once
#include <string>
#include <list>
#include <vector>
#include <map>

#include "CharFreqNode.h"

class MessageInfo
{
public:
	typedef std::map<char, double> CharToFreqMap;
	typedef std::map<char, int> CharCountMap;

	std::string msg;
	std::list<CharFreqNode> cfList;
	CharCountMap charCount;
	CharToFreqMap charCount;
	
	MessageInfo(std::string m)
		: msg(m)
	{
		CountChars();
	}

	void CountChars()
	{
		CharCountMap::iterator cci;
		for (size_t i = 0; i < msg.size(); ++i)
		{
			cci = charCount.find(msg[i]);
			if (cci != charCount.end())
			{
				cci->second++;
			}
			else
			{
				charCount.insert(std::pair<char, int>(msg[i], 1));
			}
		}
	}
	void printCharCount()
	{
		std::cout << "Letter Count " << std::endl;
		for (CharCountMap::iterator t = charCount.begin(); t != charCount.end(); ++t)
		{
			std::cout << t->first << " " << t->second << std::endl;
		}

	}
};

