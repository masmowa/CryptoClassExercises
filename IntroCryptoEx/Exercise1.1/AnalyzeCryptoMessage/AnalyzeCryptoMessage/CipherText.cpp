#include <standard-include.h>
#include "CipherText.h"
#include <iostream>
#include <map>
#include "parseUtil.h"

// advance through the message character by character
// count each occurance of a character, to create a frequency map
void CipherText::CreateMessageCharacterCount()
{
	size_t messageLen = message.size();
	for (size_t i = 0; i < messageLen; ++i)
	{
		if (message[i] != ' ')
		{
			mapCharCount[message[i]]++;
		}
	}
}
void CipherText::AnalyzeMessage()
{
	CreateMessageCharacterCount();
	// TODO create vector of characters sorted by frequency; to match englist lists.
	if (ProgramSettings::IsVerbose())
	{
		PrintCharCount();
	}
	// create a vector of characters sorted by count max to least
	CreateVectorCharactersSortedMostToLeast();
	if (ProgramSettings::IsVerbose())
	{
		PrintVectorCharCount();
	}

	AnalyzeMessageWords();
	AnalyzeMessageDigraphs();
	CreateWordSizeVectorCollection();
}
// split the message into a vector of words, seperated by ' '
// add each sort to a map if it is not there, or
// if (word exists in the map) { incriment the count }
void CipherText::AnalyzeMessageWords()
{
	// split message into an array of strings
	words = tokenize(this->message, ' ');
	MapWordCount::iterator itwd;
	for (size_t i = 0; i < words.size(); ++i)
	{
		itwd = mapWordCount.find(words[i]);
		if (itwd != mapWordCount.end())
		{
			itwd->second++;
		}
		else
		{
			mapWordCount.insert(std::pair<std::string, int>(words[i], 1));
		}
	}
}
// for each digraph (2-letter pair in text; excluding ' ') 
// if (digraph found in map) { incriment count }
// else { add digraph to map, set count to 1 }
void CipherText::AnalyzeMessageDigraphs()
{
	std::string digraph("  ");
	// 1) read message 2 char "key"
	MessageBase::MapWordCount mapDigraph;
	size_t messageLen = this->message.size();
	// 2) iterate through message counting each occurance of "key"
	for (size_t i = 1; i < messageLen; ++i)
	{
		digraph[0] = message[i - 1];
		digraph[1] = message[i];
		// filter out " a" and "a "
		if (digraph.compare(0, 1, " ") && digraph.compare(1, 1, " "))
		{
			mapDigraph[digraph]++;
		}
	}
	// now create a sorted list of digraph
	for (MessageBase::MapDigraphCount::iterator itmdgc = mapDigraph.begin(); itmdgc != mapDigraph.end(); ++itmdgc)
	{
		MessageBase::PairWordCount data(itmdgc->first, itmdgc->second);
		vectorDigraphCount.push_back(data);
	}
	// sort largest to smallest
	std::sort(vectorDigraphCount.begin(), vectorDigraphCount.end(),[](const PairWordCount& a, const PairWordCount& b) { return (a.second < b.second); });
}


void CipherText::PrintCharCount()
{
	std::cout << "Letter Count " << std::endl;
	for (MapCharCount::iterator itccm = mapCharCount.begin(); itccm != mapCharCount.end(); ++itccm)
	{
		std::cout << itccm->first << " " << itccm->second << std::endl;
	}
}


// Print words from vector of vector of string, count ; sorted by count most to least
void CipherText::PrintWordsBySizeCount(bool verbose)
{
	if (verbose)
	{
		size_t wdsize = 0;
		std::cout << "vectorWordCountBySize [" << std::endl;
		// for each vectorOfWordsSortedByFrequency in vectorOfvectorsOfWordsSortedByFrequency
		for (VectorWordSizeVectorWordCount::iterator itvvwf = vectorWordCountBySize.begin(); itvvwf != vectorWordCountBySize.end(); ++itvvwf)
		{
			std::cout << "[" << itvvwf[0].size() << "] ";
			std::cout << "[" << wdsize << "]" << std::endl;
			for (VectorWordCount::iterator itvwf = (*itvvwf).begin(); itvwf != (*itvvwf).end(); ++itvwf) {
				if (itvwf->first == "") {
					std::cout << "[empty]" << "[" << itvwf->second << "]" << std::endl;
				}
				else {
					std::cout << "[" << itvwf->first << "]" << "[" << itvwf->second << "]" << std::endl;
				}
			}
			wdsize++;
		}
		std::cout << "]" << std::endl;
	}
}


void CipherText::CreateWordSizeVectorCollection()
{
	if (ProgramSettings::IsVerbose())
	{
		std::cout << "++" << __FUNCTION__ << "()" << std::endl;
	}
	for (MapWordCount::iterator itwc = mapWordCount.begin(); itwc != mapWordCount.end(); ++itwc)
	{
		MessageBase::PairWordCount data(itwc->first, itwc->second);
		size_t pos = data.first.size();
		if (pos >= vectorWordCountBySize.size())
		{
			vectorWordCountBySize.resize(pos + 1);
		}
		vectorWordCountBySize[pos].push_back(data);
		if (pos >= vectorWordSizeVectorWords.size())
		{
			vectorWordSizeVectorWords.resize(pos + 1);
		}
		vectorWordSizeVectorWords[pos].push_back(data.first);
	}

	// NOW SORT sub-vectors by frequency (aka word count)
	
	MessageBase::VectorWordCount::iterator itvwc;
	for (MessageBase::VectorWordSizeVectorWordCount::iterator itvwswc = vectorWordCountBySize.begin(); itvwswc != vectorWordCountBySize.end(); ++itvwswc)
	{
		std::sort((*itvwswc).begin(), (*itvwswc).end(), [](const PairWordCount& a, const PairWordCount& b) { return (a.second > b.second); });
	}
	PrintWordsBySizeCount(ProgramSettings::IsVerbose());
	if (ProgramSettings::IsVerbose())
	{
		std::cout << "--" << __FUNCTION__ << "()" << std::endl;
	}
}


void CipherText::CreateVectorCharactersSortedMostToLeast()
{
	// fill vector from map
	for (MapCharCount::iterator itmcc = mapCharCount.begin(); itmcc != mapCharCount.end(); ++itmcc)
	{
		vectorCharCount.push_back(PairCharCount(itmcc->first, itmcc->second));
	}
	// sort vector from greatest to least by value data
	std::sort(vectorCharCount.begin(), vectorCharCount.end(), [](const PairCharCount& a, const PairCharCount& b) { return (a.second > b.second); });
}


// print the contents of the Char, Count vector
void CipherText::PrintVectorCharCount()
{
	std::cout << "Characters by Count:" << std::endl;
	// 
	for (VectorCharCount::iterator itvcc = vectorCharCount.begin(); itvcc != vectorCharCount.end(); ++itvcc)
	{
		std::cout << itvcc->first << " " << itvcc->second << std::endl;
	}
}


void CipherText::PrintCharByFreq()
{
	std::cout << "Characters Count order:" << std::endl;
	// 
	for (VectorCharCount::iterator itvcc = vectorCharCount.begin(); itvcc != vectorCharCount.end(); ++itvcc)
	{
		std::cout << itvcc->first;
	}
	std::cout << std::endl;
}


// construct a vector containing the first N words of size M
std::vector<std::string> CipherText::GetFirstNofWordSize(size_t count, size_t wdLen)
{
	MessageBase::VectorWords::const_iterator t = vectorWordSizeVectorWords[wdLen].begin();
	MessageBase::VectorWords::const_iterator tx = vectorWordSizeVectorWords[wdLen].begin() +2;
	MessageBase::VectorWords res(t, tx);
	return res;
}


// make a copy of the vector of words sorted by frequency, with largest frequency first
MessageBase::VectorWords CipherText::GetWordVectorOfLenN(size_t wordCount, size_t wordLen)
{
	// TODO: compute the number of values to return.
	// find the index of the last item where word count > 2
	//
	size_t lastx = 0;
	for (lastx = 0; lastx < vectorWordCountBySize[wordLen].size(); ++lastx)
	{
		if (vectorWordCountBySize[wordLen][lastx].second < 3)
		{
			break;
		}
	}
	MessageBase::VectorWords::const_iterator t = vectorWordSizeVectorWords[wordLen].begin();
	MessageBase::VectorWords::const_iterator tx = vectorWordSizeVectorWords[wordLen].begin() + lastx;
	MessageBase::VectorWords res(t, tx);
	return res;
}
