#pragma once
#include "MessageBase.h"
#include "ProgramSettings.h"

class CipherText :
	public MessageBase
{
public:
	std::string message;
	MapCharCount mapCharCount;
	MapWordCount mapWordCount;
	std::vector<std::string> words;
	bool verbose;

	MessageBase::VectorWordCount vectorWordCount;
	MessageBase::MapDigraphCount mapDigraphCount;
	MessageBase::VectorWordCount vectorDigraphCount;
	// vector of vectors where sub-vectors contain words with same char count.
	MessageBase::VectorWordSizeVectorWordCount vectorWordCountBySize;
	MessageBase::VectorWordSizeVectorWords vectorWordSizeVectorWords;

	MessageBase::VectorCharByFrequency vectorCharByFrequency;
	MessageBase::VectorCharCount vectorCharCount;


	CipherText() : verbose(ProgramSettings::IsVerbose())
	{

		InitializeMapCharCount();
	}

	CipherText(const std::string& msg) : message(msg), verbose(ProgramSettings::IsVerbose())
	{
		InitializeMapCharCount();
		AnalyzeMessage();
	}

	// fill the key, pair setting for english alphabet, initialize count(int) with 0
	// this allows us to pre-allocate 26 slots.
	void InitializeMapCharCount()
	{
		for (size_t i = 0; i < MessageBase::abc.size(); ++i)
		{
			mapCharCount.insert(std::pair<char, int>(MessageBase::abc[i], 0));
		}

	}
	void CreateMessageCharacterCount();

	void AnalyzeMessage();
	void AnalyzeMessageWords();
	void AnalyzeMessageDigraphs();

	void PrintCharCount();
	// Print words from vector of vector of string, count ; sorted by count most to least
	void PrintWordsBySizeCount(bool verbose = false);
	void CreateWordSizeVectorCollection();
	void CreateVectorCharactersSortedMostToLeast();
	// print the contents of the Char, Count vector
	void PrintVectorCharCount();
	void PrintCharByFreq();
	// construct a vector containing the first N words of size M
	MessageBase::VectorWords GetFirstNofWordSize(size_t count, size_t wdLen);
	// make a copy of the vector of words sorted by frequency, with largest frequency first
	MessageBase::VectorWords GetWordVectorOfLenN(size_t wordCount, size_t wordLen);
};

