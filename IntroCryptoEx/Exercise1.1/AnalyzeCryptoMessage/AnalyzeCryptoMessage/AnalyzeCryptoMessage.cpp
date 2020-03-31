// AnalyzeCryptoMessage.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <map>
#include <list>
#include <vector>
#include <regex>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <filesystem>

//#include <standard-include.h>
#include "ProgramSettings.h"
#include "CipherText.h"
#include "EnglishText.h"
#include "CypherKey.h"
#include <filesystem>

#include <parseUtil.h>
using namespace std;
namespace efs = std::filesystem;


std::string ReadInput(std::string const& input)
{
	efs::path inpath(input.c_str());
	//if (Verbose())
	//{
	//	std::cout << input << std::endl;
	//	//std::cout << "CWD: " << efs::current_path() << std::endl;
	//	demo_exists(inpath);
	//}
	if (!get_exists(inpath))
	{
		std::cout << "File: " << input.c_str() << " not found" << std::endl;
	}
	// get problem name
	std::ifstream fin(inpath, std::ifstream::in);
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

void WriteDTSOutputName(const std::string& prefix)
{
	std::time_t t = std::time(nullptr);
	std::tm tm = { 0 };
	errno_t err = localtime_s(&tm, &t);
	char mbstr[100] = { 0 };


	if (std::strftime(mbstr, sizeof(mbstr), "%Y%m%d-%H%M%S", &tm)) {
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

void PrintTableCTPTByWordLen(CipherText& CT, EnglishText& PT, bool verbose)
{

	if (verbose)
	{
		size_t wdsize = 0;
		std::cout << "Table of words by size by freq [" << std::endl;
		MessageBase::VectorWordSizeVectorWords::iterator itPtWdL;
		// for each vectorOfWordsSortedByFrequency in vectorOfvectorsOfWordsSortedByFrequency
		size_t ctWordLenMax = CT.vectorWordCountBySize.size();
		size_t ptWordLenMax = PT.vvWordsByFreq.size();

		for (size_t cc=0, pc=0; cc < ctWordLenMax && pc <ptWordLenMax; ++cc, ++pc)
		{
			MessageBase::VectorWordCount vecCtLN = CT.vectorWordCountBySize[cc];
			MessageBase::VectorWords     vecPtLN = PT.vvWordsByFreq[pc];

			std::cout << "[" << vecCtLN.size() << "] ";
			std::cout << "[" << wdsize << "]" << std::endl;
			std::cout << "[CT  ]" << "\t[count]" << "\t[PT]" << std::endl;
			for (size_t wdx = 0; wdx < vecCtLN.size() && wdx < vecPtLN.size(); ++wdx) {
				if (vecCtLN[wdx].first == "") {
					std::cout << "[empty]" << "\t[" << vecCtLN[wdx].second << "]\t[ ]" << std::endl;
				}
				else {
					std::cout << "[" << vecCtLN[wdx].first << "]" << "\t[" << vecCtLN[wdx].second << "]" << "\t[" << vecPtLN[wdx] << "]" << std::endl;
				}
			}
			wdsize++;
		}
		std::cout << "]" << std::endl;
	}
}

void PrintTableGuessCTPT(const MessageBase::VectorWords& CT, const MessageBase::VectorWords& PT, bool verbose)
{
	size_t guessSize = CT[0].size();
	if (verbose)
	{
		std::cout << "[word size: " << guessSize << "]" << std::endl;
		std::cout << "[CT]\t[PT]" << std::endl;
		for (size_t i = 0; i < CT.size() && i < PT.size(); ++i)
		{
			std::cout << "[" << CT[i] << "]\t[" << PT[i] << "]" << std::endl;
		}
	}
}
// new approach
// there are multiple rounds of guessing how to map High frequency CT 
// to similar High Frequency English words (PT)
// Round 0 - no memory, just use High frequency words of matching word size from CT to PT
//   0.0: match ct-word-Length-1 -> pt-word-Length-1 (there are 2, 
//       A and I A more frequent than I
//       we have a 50/50 chance of a correct guess)
//   0.1: match words 1 at a time for words of Length = 3 
//        (I do this because highest in Englist = "the" so 
//        no character overlap with 0.0
//         highest wordL3 is almost guarenteed match)
//   0.2: match wordL2, a bit tricker, possible character overlap
//        need to ensure if high-frequency-CT contains one of the preveous
//        guesses that the program "finds" an apropriate match in the PT list
//        (the previous set of gueses didn't do this, which caused jibberish)
void RunDecryptGuessingRounds(CipherText& CT, EnglishText& PT)
{
	std::cout << "++" << __FUNCTION__ << "()" << std::endl;
	static int wordLenGuessOrder[] = { 1, 3, 2, 4 };
	// guess key
	CypherKey key("Guess0");
	MessageBase::VectorWords ctWdOfLenN;
	MessageBase::VectorWords ptWdOfLenN;
	for (size_t i = 0; i < 4; ++i)
	{
		size_t sel = wordLenGuessOrder[i];
		// now iterate through the guesses
		// for wordLen == 1 it is easy
		ctWdOfLenN = CT.GetWordVectorOfLenN(2, sel);
		std::cout << "[CT].size() : " << ctWdOfLenN.size() << std::endl;
		ptWdOfLenN = PT.GetWordVectorOfLenN(ctWdOfLenN.size(), sel);
		PrintTableGuessCTPT(ctWdOfLenN, ptWdOfLenN, ProgramSettings::IsVerbose());
	}
	std::cout << "--" << __FUNCTION__ << "()" << std::endl;
}

void DecryptMessage(CipherText& CT, EnglishText& eng)
{
	std::cout << "++" << __FUNCTION__ << "()" << std::endl;
	static int sizeOrder[] = { 4, 3, 2, 1 };
	// guess key
	CypherKey key("Guess0");
	// Pre-guess words with 1 char, there are 2

	// todo: make decipher into aset of trial attempts 
	// with a prompt to ask if the current guess is acceptable
	// if it is not, pop the last guess off the stack
	// 

	for (size_t cc = 0; cc < 4; ++cc)
	{
		int sel = sizeOrder[cc];
		MessageBase::VectorWords ctWdLN;
		MessageBase::VectorWords ptWdLN;
		if (sel == 1)
		{
			ctWdLN = CT.vectorWordSizeVectorWords[sel];
			ptWdLN = eng.monoWdByFreq;
		}
		else
		{
			ctWdLN = CT.GetFirstNofWordSize(2, sel);
			ptWdLN = eng.GetFirstNofWordSize(2, sel);
		}
		for (size_t z = 0; z < ctWdLN.size(); ++z)
		{
			std::cout << "CT[" << ctWdLN[z] << "] guess PT[" << ptWdLN[z] << "]\n";
		}
		key.SetKeyValues(ctWdLN, ptWdLN);
		// after we set some guesses, 
		// perform some attempt at decryption with the 
		// current partial key.  show the message and the 
		// partially decrypted message to the user
		// prompt for pass / fail judgement
		// if pass then procede to next set of guesses
		std::cout << std::endl;
	}
	key.SetKeyValuesFromCtCharCount(CT.vectorCharCount, eng.alphaByFreq);
	key.PrintKey();
	CT.PrintCharByFreq();
	eng.PrintCharByFreq();
	std::cout << std::endl;
	std::string decrypted = key.Decipher(CT.message);
	std::cout << "Decryption guess 0: " << std::endl;
	std::cout << decrypted << std::endl;

	std::cout << "--" << __FUNCTION__ << "()" << std::endl;
}
void ProcessInput(std::string const& input)
{
	WriteDTSOutputName("DecryptMessage");
	string ct = ReadInput(input);
	CipherText msgCt(ct);
	EnglishText english;

	std::cout << "Percent " << std::endl;

	msgCt.PrintWordsBySizeCount();

	PrintTableCTPTByWordLen(msgCt, english, true);
	//DecryptMessage(msgCt, english);
	RunDecryptGuessingRounds(msgCt, english);
}

int main()
{
	for (auto& p : efs::directory_iterator("input"))
	{
		string ps = p.path().string();
		ProcessInput(ps);
	}
}
