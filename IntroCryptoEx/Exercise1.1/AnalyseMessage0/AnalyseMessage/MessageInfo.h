#pragma once
#include <string>
#include <list>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>

#include "CharFreqNode.h"
#include "parseUtil.h"
#include "MessageInfo_base.h"

class MessageInfo : public MessageInfo_base
{
public:
	typedef std::list<CipherToPlain> MatchCTtoPT;
	typedef std::map<char, char> CipherKeyMap;


	std::string msg;
	std::vector<string> words;

	std::list<CharFreqNode> cfList;
	CharCountMap charCount;
	CharFreqPercentMap charPercentMap;
	WordCountMap wordCount;
	WordFreqPercentMap wordPercentMap;
	VectorListWordFreq wordsByCharCount;
	ListListWordFreq wordsListsByFreq;
	CipherKeyMap cipherKeyMap;
	MapCTtoPT mapCtPtGuess;
	MessageInfo_base::ListWordCount listDigraphCount;
	std::list<std::string> listDigraphByFreq;

	MessageInfo(std::string m)
		: msg(m)
	{
		CountChars();
		CountWords();
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
	void CountWords()
	{
		words = tokenize(msg, ' ');
		WordCountMap::iterator itwd;
		for (size_t i = 0; i < words.size(); ++i)
		{
			itwd = wordCount.find(words[i]);
			if (itwd != wordCount.end())
			{
				itwd->second++;
			}
			else
			{
				wordCount.insert(std::pair<std::string, int>(words[i], 1));
			}
		}

	}
	void printCharCount()
	{
		std::cout << "Letter Count " << std::endl;
		for (CharCountMap::iterator itccm = charCount.begin(); itccm != charCount.end(); ++itccm)
		{
			std::cout << itccm->first << " " << itccm->second << std::endl;
		}

	}
	void printWordCount()
	{
		std::cout << "Word Count " << std::endl;
		for (WordCountMap::iterator it = wordCount.begin(); it != wordCount.end(); ++it)
		{
			std::cout << it->first << " " << it->second << std::endl;
		}

	}
	void CalcCharPercent()
	{
		size_t ctcount = charCount.size();
		CharFreqPercentMap::iterator itfc;
		for (CharCountMap::iterator itccm = charCount.begin(); itccm != charCount.end(); ++itccm)
		{
			double freq = static_cast<double>(itccm->second) / static_cast<double>(ctcount);
			charPercentMap.insert(std::pair<char,double>(itccm->first, freq));
		}
	}
	void CalcWordPercent()
	{
		size_t wdcount = wordCount.size();
		size_t wdSizeCount = 0;			// count 
		// there should be 0 words with 0 characters so, initialize element 0 with 0 element
		WordFreqPercentMap::iterator itwfc;

		for (WordCountMap::iterator itwcm = wordCount.begin(); itwcm != wordCount.end(); ++itwcm)
		{
			double freq = static_cast<double>(itwcm->second) / static_cast<double>(wdcount);
			PairWordFreq data(itwcm->first, freq);
			if (itwcm->first == "")
			{
				ListWordFreq v;
				v.push_back(data);
				if (wordsByCharCount.empty()) {
					wordsByCharCount.push_back(v);
				}
				else {
					wordsByCharCount[0] = v;
				}
			}
			else {
				wordPercentMap.insert(data);
				size_t pos = data.first.size();
				if (pos >= wordsByCharCount.size()) {
					wordsByCharCount.resize(pos + 1);
				}
				wordsByCharCount[pos].push_back(data);
			}
		}
		// create sorted vector of words of size N smallest to frequency to largest
		// note seems I cannot just do not-less-than that causes an exception (probably for )
		VectorListWordFreq::iterator itVecListWF;
		ListWordFreq::iterator itListWF;
		for (VectorListWordFreq::iterator itvlwf = wordsByCharCount.begin(); itvlwf != wordsByCharCount.end(); ++itvlwf)
		{
			(*itvlwf).sort([](const PairWordFreq& a, const PairWordFreq& b) { return (a.second < b.second); });
			// now reverse the sort order of the sum-list, because I want the word with the greatest frequency to be first
			(*itvlwf).reverse();
		}
		// simplify accessing words in most frequent order (highest to lowest)
		//std::reverse(wordsByCharCount.begin(), wordsByCharCount.end());

	}
	void printCharPercent()
	{
		std::cout << "Letter Percent " << std::endl;
		;
		for (CharFreqPercentMap::iterator itcfp = charPercentMap.begin(); itcfp != charPercentMap.end(); ++itcfp)
		{
			std::cout << itcfp->first << " " << itcfp->second << std::endl;
		}

	}
	void SeperateWordsByCharacterCount()
	{
		for (WordFreqPercentMap::iterator itwfc = wordPercentMap.begin(); itwfc != wordPercentMap.end(); ++itwfc)
		{
		}
	}
	void printWordPercent()
	{
		std::cout << "Word Percent " << std::endl;
		for (WordFreqPercentMap::iterator itwfc = wordPercentMap.begin(); itwfc != wordPercentMap.end(); ++itwfc)
		{
			std::cout << itwfc->first << " " << itwfc->second << std::endl;
		}
	}
	void PrintWordsBySizePercent()
	{
		size_t wdsize = 0;
		for (VectorListWordFreq::iterator itvlwf = wordsByCharCount.begin(); itvlwf != wordsByCharCount.end(); ++itvlwf)
		{
			std::cout << "[" << wdsize << "]" << std::endl;
			for (ListWordData::iterator itlwd = (*itvlwf).begin(); itlwd != (*itvlwf).end(); ++itlwd) {
				if (itlwd->first == "") {
					std::cout << "[empty]" << "[" << itlwd->second << "]" << std::endl;
				}
				else {
					std::cout << "[" << itlwd->first << "]" << "[" << itlwd->second << "]" << std::endl;
				}
			}
			wdsize++;
		}
	}
	void GuessWordsFromNCharWidth(size_t wdSize, const VectorListWordByFreq& vlwbf) {

		for (size_t i = wdSize; i > 0; --i)
		{
			GuessWordsByFreqAt(i, vlwbf[i]);
		}
	}

	void GuessWordsByFreqAt(size_t wdSize, const MessageInfo_base::ListWords& enWordList)
	{
		// 1) get the ultimate and pen-ultimate words of size wdSize
		// 2) get the ultiate and pen-ultimate words of size wdSize -1
		// 3) catagorize characters that match in seected words
		// 4) pick english words that have maximum match as guess
		// get list of cipher text (CT) of words of size wdSize
		
		VWords CtAszWords = this->GetTop3CTWords(wdSize);
		

		ListWordFreq& lstCtWdFreq = wordsByCharCount[wdSize];

		// get list of cipher text (CT) of words of size wdSize-1
		ListWordFreq& lstCtWdFreqM = wordsByCharCount[wdSize-1];

		size_t ndxWdFreq = lstCtWdFreq.size() - 1;

		MessageInfo_base::ListWordFreq::iterator ctWdFqIt = lstCtWdFreq.begin();
		std::advance(ctWdFqIt, ndxWdFreq-1);

		MessageInfo_base::ListWords::const_iterator enwit = enWordList.begin();

		std::cout << "ndx[" << ndxWdFreq << "] ";
		std::cout << "[" << ctWdFqIt->first << "," << ctWdFqIt->second << "]" << std::endl;
		std::advance(ctWdFqIt, 1);
		std::cout << "ndx[" << ndxWdFreq+1 << "] ";
		std::cout << "[" << ctWdFqIt->first << "," << ctWdFqIt->second << "]" << std::endl;
		std::cout << "english: " << "[" << *enwit << "]" << std::endl;

		//std::vector<std::string> CTGuess
	}
	std::vector<std::string> GetTop3CTWords(size_t wdSz)
	{
		VWords top3;

		ListWordFreq& lstCtWdFreq = wordsByCharCount[wdSz];
		size_t ndxWdFreq = lstCtWdFreq.size() - 3;
		MessageInfo_base::ListWordFreq::iterator ctWdFqIt = lstCtWdFreq.begin();
		std::cout << "CT: "; // << most << " mid: " << mid << " least: " << least
		for (size_t i = 0; i < 3 && ctWdFqIt != lstCtWdFreq.end(); ++i, ++ctWdFqIt)
		{
			std::cout << ctWdFqIt->first << " ";
			top3.push_back(ctWdFqIt->first);
		}
		std::cout << std::endl;
		return top3;
	}

	MessageInfo_base::ListWordFreq& GetListWordFreqAtLen(size_t wdSz)
	{
		return  wordsByCharCount[wdSz];;
	}

	// make a std::list as a copy of the words from the 
	// "frequency sorted" pair(word, freq) list, for words of size wdSz
	// 
	// param: size_t wdSz : size of words we want
	VWords GetWordVectorAt(size_t wdSz)
	{
		ListWords listWd;
		MessageInfo_base::VWords vCtWords;

		ListWordFreq& lstCtWdFreq = wordsByCharCount[wdSz];
		std::stringstream title;

		title << "CT(" << wdSz << "): "; 
		for (MessageInfo_base::ListWordFreq::iterator ctWdFqIt = lstCtWdFreq.begin(); ctWdFqIt != lstCtWdFreq.end(); ++ctWdFqIt)
		{
			//std::cout << ctWdFqIt->first << " ";
			vCtWords.push_back(ctWdFqIt->first);
		}
		//std::cout << std::endl;
		MessageInfo_base::PrintVectorWord(wdSz, vCtWords, title.str());
		return vCtWords;
	}

	void GuessWordWithNChar(size_t wdSize, const VectorListWordByFreq& vlwbf) {
		if (4 == wdSize && wdSize < vlwbf.size()) {
			Guess4CharWord(vlwbf[wdSize]);
		}
	}
	void Guess4CharWord(const MessageInfo_base::ListWords& enWord4Char)
	{
		std::cout << "4 character words:" << std::endl;
		VectorListWordFreq::iterator vlwfIt = wordsByCharCount.begin();
		size_t ndx = 0;
		for (vlwfIt = wordsByCharCount.begin(), ndx = 0; vlwfIt != wordsByCharCount.end(); ++vlwfIt, ++ndx)
		{
			if (ndx == 4) {
				break;
			}
			else { continue;  }
		}
		ListWordFreq::iterator lwfit = vlwfIt->begin();
		PairWordFreq pwfval = vlwfIt->back();
		MessageInfo_base::ListWords::const_iterator enwit = enWord4Char.begin();
		std::cout << "first: " << "[" << lwfit->first << "," << lwfit->second << "]" << std::endl;
		std::cout << "last: " << "[" << pwfval.first << "," << pwfval.second << "]" << std::endl;
		std::cout << "english: " << "[" << *enwit <<  "]" << std::endl;


	}

	// calculate a "word score" for the string
	// word score is a count of the occurance of eachcharacter in the word
	// count position is based upon the initial position of the character
	// ex. 
	//	"the"   : "111"
	//	"that"  : "211" 
	//  "this"  : "1111"
	//  "data"  : "121"
	std::string WordScore(const std::string& word)
	{
		return MessageInfo_base::WordScore(word);
	}

	std::list<std::string> MakeBigraphFrequencySortedList()
	{
		MessageInfo_base::MapDigraphCount mapDigraphCount;
		MessageInfo_base::VectorWordCount vectorDigraphCount;
		std::string digraph("  ");
		// 1) read message 2 char "key"
		MessageInfo_base::WordCountMap mapDigraph;
		size_t msgLen = this->msg.size();
		// 2) iterate through message counting each occurance of "key"
		for (size_t i = 1; i < msgLen; ++i)
		{
			digraph[0] = msg[i - 1];
			digraph[1] = msg[i];
			// filter out " a" and "a "
			if (digraph.compare(0, 1, " ") && digraph.compare(1, 1, " "))
			{
				mapDigraph[digraph]++;
			}
		}
		// now create a sorted list of digraph
		for (MessageInfo_base::MapDigraphCount::iterator itmdgc = mapDigraph.begin(); itmdgc != mapDigraph.end(); ++itmdgc)
		{
			MessageInfo_base::PairWordCount data(itmdgc->first, itmdgc->second);
			listDigraphCount.push_back(data);
		}
		// sort largest to smallest
		listDigraphCount.sort([](const PairWordCount& a, const PairWordCount& b) { return (a.second > b.second); });
		PrintListWordCount(2, listDigraphCount, "[DIGRAPH LIST - BY FREQUENCY]");

		// now get a list with only the digraph elements (easier to work with for key editing)
		for (MessageInfo_base::ListDigraphCount::iterator itlwc = listDigraphCount.begin(); itlwc != listDigraphCount.end(); ++itlwc)
		{
			listDigraphByFreq.push_back(itlwc->first);
		}
		return listDigraphByFreq;
	}
};

