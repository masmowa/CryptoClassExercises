#pragma once
#include <string>
#include <list>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>

class MessageBase
{
public:
	typedef std::map<char, int> MapCharCount;
	typedef std::map<char, double> MapCharFreq;

	typedef std::map<std::string, double> MapStringFreq;

	typedef std::map<std::string, int> MapWordCount;
	typedef std::map<std::string, std::string> MapWord;
	typedef std::pair<std::string, int> PairWordCount;
	typedef std::vector<PairWordCount> VectorWordCount;
	typedef std::pair<std::string, std::string> PairWordWord;
	typedef VectorWordCount VectorDigraphCount;
	typedef MapWordCount MapDigraphCount;
	typedef MapStringFreq MapWordFreq;

	typedef std::pair<char, int> PairCharCount;
	typedef std::vector<char> VectorCharByFrequency;
	typedef std::vector< PairCharCount > VectorCharCount;
	typedef std::vector<std::string> VectorWords;
	typedef std::vector<VectorWords> VectorWordSizeVectorWords;
	typedef std::vector<VectorWordCount> VectorWordSizeVectorWordCount;
	typedef std::map<char, double> MapCharToFreq;


	static std::vector<char> abc;

public:
	static std::map<char, int> CountChars(const std::string& word)
	{
		MapCharCount::iterator cci;
		MapCharCount mpChCt;
		for (size_t i = 0; i < word.size(); ++i)
		{
			cci = mpChCt.find(word[i]);
			if (cci != mpChCt.end())
			{
				cci->second++;
			}
			else
			{
				mpChCt.insert(std::pair<char, int>(word[i], 1));
			}
		}
		return mpChCt;
	}

};

