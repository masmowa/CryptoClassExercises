// AnalyseMessage.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <map>
#include <list>
#include <vector>
#include <regex>
#include <algorithm>
#include <ctime>
#include <iomanip>

#include <standard-include.h>
#include "CypherKey.h"

#include "EnCharFrequency.h"
#include "CharPtFreqCtFreq.h"
#include "CharFreqNode.h"
#include "MessageInfo.h"

using namespace std;

typedef std::map<char, int> CharCount;
typedef std::map<char, CharPtFreqCtFreq> CharFreqMap;
typedef std::map<char, int> CharCountMap;
typedef std::pair<char, int> PairCharCount;
typedef std::vector<std::string> VWords;
typedef std::map<std::string, int> WordCountMap;
typedef std::pair<std::string, CharCountMap> PairWordToCharCountMap;
typedef std::map<std::string, CharCountMap> MapWordToCharCountMap;




std::string ReadInput(std::string const& input)
{
	efs::path inpath(input.c_str());
	if (Verbose())
	{
		std::cout << input << std::endl;
		//std::cout << "CWD: " << efs::current_path() << std::endl;
		demo_exists(inpath);
	}
	if (!get_exists(inpath))
	{
		std::cout << "File: " << input.c_str() << " not found" << std::endl;
	}
	// get problem name
	std::ifstream fin(inpath);
	std::string line;
	std::getline(fin, line);
	string problemName = line;
	// get input ciphertext
	std::getline(fin, line);
	vector<string> intoks = tokenize(line, ':');
	for (size_t i = 0; i < intoks.size(); ++i)
	{
		cout << intoks[i] << std::endl;
	}


	return intoks[1];
}

void GetCharCountMapFromWord(const std::string& val, CharCountMap& ccMap)
{
	size_t wdsz = val.length();
	for (size_t i = 0; i < wdsz; ++i)
	{
		CharCountMap::iterator itc = ccMap.find(val[i]);
		if (itc != ccMap.end())
		{
			itc->second++;
		}
		else
		{
			ccMap.insert(PairCharCount(val[i], 1));
		}
	}
}

void PrintLNCharCount(size_t len, const std::string & word, CharCountMap& ccm, std::string score)
{
	std::cout << "word [" << word << "] length[" << word.length()  << "] score:"<< score<< ": ";
	for (CharCountMap::iterator itccm = ccm.begin(); itccm != ccm.end(); ++itccm)
	{
		std::cout << "[" << itccm->first << " " << itccm->second << "] ";
	}
	std::cout << std::endl;
}

MessageInfo_base::MapWordPair MakeWordScoreMap(const MessageInfo_base::ListWords& listWord, size_t wdLen, const std::string& title)
{
	MessageInfo_base::MapWordPair res;
	MessageInfo_base::PrintWordsFromList(title, listWord);
	for (MessageInfo_base::ListWords::const_iterator itcwd = listWord.begin(); itcwd != listWord.end();  ++itcwd)
	{
		CharCountMap tmpMap;
		std::string score;
		GetCharCountMapFromWord(*itcwd, tmpMap);
		score = MessageInfo_base::WordScore(*itcwd);
		res.insert(std::pair<std::string, std::string>(*itcwd, score));
		PrintLNCharCount(wdLen, *itcwd, tmpMap, score);
		//top3CtMapWdToCCL4.insert(PairWordToCharCountMap(*itcwd, tmpMap));
	}


	return res;
}

MessageInfo_base::MapWordPair MakeWordScoreMap(const MessageInfo_base::VWords& vectWord, size_t wdLen, const std::string& title)
{
	MessageInfo_base::MapWordPair res;
	MessageInfo_base::PrintWordsFromList(title, vectWord);
	for (MessageInfo_base::VWords::const_iterator itcwd = vectWord.begin(); itcwd != vectWord.end();  ++itcwd)
	{
		CharCountMap tmpMap;
		std::string score;
		GetCharCountMapFromWord(*itcwd, tmpMap);
		score = MessageInfo_base::WordScore(*itcwd);
		res.insert(std::pair<std::string, std::string>(*itcwd, score));
		PrintLNCharCount(wdLen, *itcwd, tmpMap, score);
		//top3CtMapWdToCCL4.insert(PairWordToCharCountMap(*itcwd, tmpMap));
	}


	return res;
}

MessageInfo_base::ListWords GuessPTFromCTScore(const std::string& word, const std::string& score, const MessageInfo_base::MapWordPair& mapWordScorePt, const std::string& CT)
{
	MessageInfo_base::ListWords listWords;
	//MessageInfo_base::MapWordPair::const_iterator itpt = 
	for (MessageInfo_base::MapWordPair::const_iterator it = mapWordScorePt.begin(); it != mapWordScorePt.end(); ++it)
	{
		if (it->second == score)
		{
			listWords.push_back(it->first);
		}
	}
	return listWords;
}

// for words in WordScoreCt, to words i mapWordScorePt whos scores match
MessageInfo_base::MapCTtoPTList MakeSubstListFromWordScores(
	const MessageInfo_base::MapWordPair& mapWordScoreCt, 
	const MessageInfo_base::MapWordPair& mapWordScorePt, 
	const MessageInfo_base::ListWords& wordList, 
	MessageInfo& ct, 
	EnglishData& eng)
{
	MessageInfo_base::MapCTtoPTList mapCttoPtList;
	// holds guess of word
	MessageInfo_base::ListWords listWords;
	std::vector<CypherKey> rgGuessKeys;

	// find PT words with scores that match CT
	for (MessageInfo_base::ListWords::const_iterator itct = wordList.begin(); itct != wordList.end(); ++itct)
	{

		MessageInfo_base::MapWordPair::const_iterator itCtScore = mapWordScoreCt.find(*itct);	// .second;
		MessageInfo_base::ListWords guesses = 
			GuessPTFromCTScore(*itct, itCtScore->second, mapWordScorePt, ct.msg);
		size_t count = 0;
		for (MessageInfo_base::ListWords::iterator ptIt = guesses.begin(); ptIt != guesses.end(); ++ptIt, ++count) {
			// todo: create a copy of the cipher message,
			//std::string msgcpy = ct.msg;

			//std::string PT = *it;
			//std::transform(PT.begin(), PT.end(), PT.begin(), ::toupper);

			std::string PTGuess;
			if (rgGuessKeys.size() != 0)
			{
				bool keyUpdated = false;
				// cycle through keys add new guess
				for (std::vector<CypherKey>::iterator ckit = rgGuessKeys.begin(); ckit != rgGuessKeys.end(); ++ckit)
				{

					if (ckit->SetKeyValues(itCtScore->first, *ptIt))
					{
						// no collision
						keyUpdated = true;
						break;
					}
					else
					{
						// check next entry
						continue;
					}

				}
				if (!keyUpdated)
				{
					std::stringstream ssn;
					ssn << "KeyGuess(" << count << ")";
					// no guesses yet add the first cypher key guess
					CypherKey gk(ssn.str());
					// add new key-guess with some substitutions
					gk.SetKeyValues(*itct, *ptIt);
					gk.PrintKey();

					// replace CT with PT
					PTGuess = gk.Decipher(ct.msg);

					rgGuessKeys.push_back(gk);

				}
			}
			else
			{
				std::stringstream ssn;
				ssn << "KeyGuess(" << count << ")";
				// no guesses yet add the first cypher key guess
				CypherKey gk(ssn.str());
				// add new key-guess with some substitutions
				gk.SetKeyValues(*itct, *ptIt);
				gk.PrintKey();

				// replace CT with PT
				PTGuess = gk.Decipher(ct.msg);

				rgGuessKeys.push_back(gk);
			}

			// print message
			std::cout << PTGuess << std::endl;
		}
	}
	return mapCttoPtList;
}

// for words in WordScoreCt, to words i mapWordScorePt whos scores match
MessageInfo_base::MapCTtoPTList MakeSubstListFromWordScores(
	const MessageInfo_base::MapWordPair& mapWordScoreCt, 
	const MessageInfo_base::MapWordPair& mapWordScorePt, 
	const MessageInfo_base::VWords& vectWords, 
	MessageInfo& ct, 
	EnglishData& eng)
{
	MessageInfo_base::MapCTtoPTList mapCttoPtList;
	// holds guess of word
	MessageInfo_base::ListWords listWords;
	std::vector<CypherKey> rgGuessKeys;

	// find PT words with scores that match CT
	for (MessageInfo_base::VWords::const_iterator itct = vectWords.begin(); itct != vectWords.end(); ++itct)
	{

		MessageInfo_base::MapWordPair::const_iterator itCtScore = mapWordScoreCt.find(*itct);	// .second;
		MessageInfo_base::ListWords guesses = 
			GuessPTFromCTScore(*itct, itCtScore->second, mapWordScorePt, ct.msg);
		size_t count = 0;
		for (MessageInfo_base::ListWords::iterator ptIt = guesses.begin(); ptIt != guesses.end(); ++ptIt, ++count) {
			// todo: create a copy of the cipher message,
			//std::string msgcpy = ct.msg;

			//std::string PT = *it;
			//std::transform(PT.begin(), PT.end(), PT.begin(), ::toupper);

			std::string PTGuess;
			if (rgGuessKeys.size() != 0)
			{
				bool keyUpdated = false;
				// cycle through keys add new guess
				for (std::vector<CypherKey>::iterator ckit = rgGuessKeys.begin(); ckit != rgGuessKeys.end(); ++ckit)
				{

					if (ckit->SetKeyValues(itCtScore->first, *ptIt))
					{
						// no collision
						keyUpdated = true;
						break;
					}
					else
					{
						// check next entry
						continue;
					}

				}
				if (!keyUpdated)
				{
					std::stringstream ssn;
					ssn << "KeyGuess(" << count << ")";
					// no guesses yet add the first cypher key guess
					CypherKey gk(ssn.str());
					// add new key-guess with some substitutions
					gk.SetKeyValues(*itct, *ptIt);
					gk.PrintKey();

					// replace CT with PT
					PTGuess = gk.Decipher(ct.msg);

					rgGuessKeys.push_back(gk);

				}
			}
			else
			{
				std::stringstream ssn;
				ssn << "KeyGuess(" << count << ")";
				// no guesses yet add the first cypher key guess
				CypherKey gk(ssn.str());
				// add new key-guess with some substitutions
				gk.SetKeyValues(*itct, *ptIt);
				gk.PrintKey();

				// replace CT with PT
				PTGuess = gk.Decipher(ct.msg);

				rgGuessKeys.push_back(gk);
			}

			// print message
			std::cout << PTGuess << std::endl;
		}
	}
	return mapCttoPtList;
}

// I had an idea here
// 1) start guess with 1 letter words (there are only 2!)
// 2) add guess with 3 letter word matching using 1 letter word as hint for which 2 letter words
// 
// thus with 1 letter words w, b
// there are 2 keys k1 = { (w,a), (m, i), ...}; k2 = { (w, i), (m, a), ...}
// now most frequent 2 char words are [ "xj", "bj", "wi", "yt", "mk", "dj", "wk", "mb", "pr", "lr", "kj", "kj" ]
// 2 character english words by frequency are ["of", "to", "in", "it", "is", "be", "as", "at", "so", "we", "he", "by", "or ", "on", "do", "if", "me", "my", "up", "an", "go", "no", "us", "am"] 
// this gives guesses for ["wi"] = [ "a?" ] or ["wi"] = ["i?"] this can be guessed to  ["wi"] = ["as", "at", "an", "am"] or ["wi"] = ["in", "it", "is", "if" ]
// since two letter words consist of (consinent, vowel) pair (no duplicate) and the vowel list = [ 'a', 'e', 'i', 'o', 'u', 'y' ] 
// and 'a' and 'i' are already mapped this means [ 'e', 'o', 'u', 'y' ] are remaining to 
// another thing is to count all digraph (eng = ["th", "er", "on", "an", "re", "he", "in", "ed", "nd", "ha", "at", "en", "es", "of", "or", "nt", "ea", "ti", "to", "it", "st", "io", "le", "is", "ou", "ar", "as", "de", "rt", "ve" ]
// then I can find tri-graph starting with "th" this should be the most popular and will map to the word "the", with "the" I can guess all 't' and 'h' values

void GuessKeysSmallestToLargest(MessageInfo& ct, EnglishData& eng)
{
	typedef MessageInfo_base::MapWordPair MapKey;

	std::map<std::string, CypherKey> mapOfCypherKey;

	MessageInfo_base::ListWords listDigraphWordByCount =
		ct.MakeBigraphFrequencySortedList();
	MessageInfo_base::VWords vectCtWordsL1 = ct.GetWordVectorAt(1);
	MessageInfo_base::VWords vectPtWordsL1 = eng.GetWordVectorAt(1);
	// create key-name based on words in vector
	std::stringstream kn;
	for (const auto& w : vectCtWordsL1)
	{
		kn << w;
	}
	for (const auto& w : vectPtWordsL1)
	{
		kn << w;
	}

	CypherKey key0(kn.str());
	key0.SetKeyValues(vectCtWordsL1, vectPtWordsL1);
	std::string CTPT0 = key0.Decipher(ct.msg);
	std::cout << CTPT0 << std::endl;
	
	mapOfCypherKey[kn.str()] = key0;

	kn.str("");
	for (VWords::const_reverse_iterator w = vectCtWordsL1.rbegin(); w != vectCtWordsL1.rend(); ++w)
	{
		kn << *w;
	}
	for (VWords::const_reverse_iterator w = vectPtWordsL1.rbegin(); w != vectPtWordsL1.rend(); ++w)
	{
		kn << *w;
	}
	CypherKey key1(kn.str());
	key1.SetKeyValuesRev(vectCtWordsL1, vectPtWordsL1);

	std::string CTPT1 = key1.Decipher(ct.msg);
	std::cout << CTPT1 << std::endl;

	mapOfCypherKey[kn.str()] = key1;

	MessageInfo_base::VWords vectCtWordsL2 = ct.GetWordVectorAt(2);
	MessageInfo_base::VWords vectPtWordsL2 = eng.GetWordVectorAt(2);

	for (MessageInfo_base::VWords::iterator itct1 = vectCtWordsL1.begin(); itct1 != vectCtWordsL1.end(); ++itct1)
	{
		// guess unknown value in multi-char-word
		for (MessageInfo_base::VWords::iterator itct2 = vectCtWordsL2.begin(); itct2 != vectCtWordsL2.end(); ++itct2)
		{
			size_t pos = itct2->find(itct1[0]);
			if (pos != std::string::npos)
			{
				// found value
				// get the position of one of the characters != known-CT
				size_t ctvpos = (pos + 1) % itct2->length();
				char cpt = key1.key[(*itct1)[0]];

				// find plain-text word containing character matching "known" key-value
				for (MessageInfo_base::VWords::iterator itpt2 = vectPtWordsL2.begin(); itpt2 != vectPtWordsL2.end(); ++itpt2) {
					size_t ptpos = itpt2->find(cpt);
					if (ptpos != std::string::npos)
					{
						// found word with char matching key-plain-text-value
						itct2;
					}
				}
			}
		}

	}
	MessageInfo_base::VWords vectCtWordsL3 = ct.GetWordVectorAt(3);
	MessageInfo_base::VWords vectPtWordsL3 = eng.GetWordVectorAt(3);

}

// abandon
void DirectKeyGuessing(MessageInfo& ct, EnglishData& eng)
{
	GuessKeysSmallestToLargest(ct, eng);
}
void DirectWordGuessingFromL4(MessageInfo& ct, EnglishData& eng)
{

	MapWordToCharCountMap ctMapWdToCCL4;
	MessageInfo_base::MapWordPair mapWordScoreCtL4;
	MessageInfo_base::MapWordPair mapWordScoreCtL3;
	MessageInfo_base::MapWordPair mapWordScorePtL4;
	MessageInfo_base::MapWordPair mapWordScorePtL3;
	MessageInfo_base::VWords vectCtWordsL4 = ct.GetWordVectorAt(4);
	mapWordScoreCtL4 = MakeWordScoreMap(vectCtWordsL4, 4, "[CIPHER TEXT L4]");

	MessageInfo_base::VWords vectPtWordsL4 = eng.GetWordVectorAt(4);
	mapWordScorePtL4 = MakeWordScoreMap(vectPtWordsL4, 4, "[PLAIN TEXT L4]");


	MessageInfo_base::MapCTtoPTList guessList =
		MakeSubstListFromWordScores(mapWordScoreCtL4, mapWordScorePtL4, vectCtWordsL4, ct, eng);

	MapWordToCharCountMap top3CtMapWdToCCL3;
	MessageInfo_base::VWords vectCtWordsL3 = ct.GetWordVectorAt(3);
	mapWordScoreCtL3 = MakeWordScoreMap(vectCtWordsL3, 3, "[CIPHER TEXT L3]");

	//VWords top3PtwordsL3 = eng.GetTop3PTWords(3);
	CharCountMap top3PtL3ccm;
	//MapWordToCharCountMap top3PtMapWdToCCL3;
	MessageInfo_base::VWords vectPtWordsL3 = eng.GetWordVectorAt(3);
	mapWordScorePtL3 = MakeWordScoreMap(vectPtWordsL3, 3, "[PLAIN TEXT L3]");

	// now find a match of top score CT to PT
}

void WriteDTSOutputName(const std::string& prefix)
{
	std::time_t t = std::time(nullptr);
	std::tm tm = { 0 };
	errno_t err = localtime_s(&tm, &t);
	char mbstr[100] = { 0 };


	if (std::strftime(mbstr, sizeof(mbstr), "%Ym%d-%H%M%S", &tm)) {
		std::cout << mbstr << '\n';
	}
	stringstream ssname;
	if (prefix.empty()) {
		ssname << "output-" << mbstr << ".txt";// << std::endl;
	}
	else {
		ssname << prefix << "-output-" << mbstr << ".txt";
	}
	std::cout << ssname.str() << std::endl;
}
void ProcessInput(std::string const& input)
{
	string ct = ReadInput(input);
	MessageInfo msgInfo(ct);
	EnglishData english;

	WriteDTSOutputName("");
	//msgInfo.printCharCount();
	//msgInfo.printWordCount();
	msgInfo.CalcCharPercent();
	msgInfo.CalcWordPercent();
	std::cout << "Percent " << std::endl;
	//msgInfo.printCharPercent();
	//msgInfo.printWordPercent();
	msgInfo.PrintWordsBySizePercent();

	//msgInfo.GuessWordWithNChar(4, english.vlWordsByFreq);
	//msgInfo.GuessWordsFromNCharWidth(4, english.vlWordsByFreq);
	//DirectWordGuessingFromL4(msgInfo, english);
	DirectKeyGuessing(msgInfo, english);
}
int main()
{
    //std::cout << "Hello World!\n";
	for (auto& p : efs::directory_iterator("input"))
	{
		string ps = p.path().string();
		ProcessInput(ps);
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
