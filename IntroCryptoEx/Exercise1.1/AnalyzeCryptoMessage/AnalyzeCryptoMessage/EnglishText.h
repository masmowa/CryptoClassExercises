#pragma once
#include "MessageBase.h"
class EnglishText :
	public MessageBase
{
public:
	MapCharFreq ctf;
	std::vector<char> alphaByFreq;
	VectorWords monoWdByFreq;
	VectorWords wd2ByFreq;
	VectorWords al2ByFreq;
	VectorWords al2by2ByFreq;
	VectorWords wd3ByFreq;
	VectorWords wd4ByFreq;
	VectorCharByFrequency neverdouble;
	VectorWordSizeVectorWords vvWordsByFreq;

	EnglishText()
	{
		ctf = {
			std::pair<unsigned char, double>('a', 0.0817),
			std::pair<unsigned char, double>('b', 0.0150),
			std::pair<unsigned char, double>('c', 0.0278),
			std::pair<unsigned char, double>('d', 0.0425),
			std::pair<unsigned char, double>('e', 0.1270),
			std::pair<unsigned char, double>('f', 0.0223),
			std::pair<unsigned char, double>('g', 0.0202),
			std::pair<unsigned char, double>('h', 0.0609),
			std::pair<unsigned char, double>('i', 0.0697),
			std::pair<unsigned char, double>('j', 0.0015),
			std::pair<unsigned char, double>('k', 0.0077),
			std::pair<unsigned char, double>('l', 0.0403),
			std::pair<unsigned char, double>('m', 0.0241),
			std::pair<unsigned char, double>('n', 0.0675),
			std::pair<unsigned char, double>('o', 0.0751),
			std::pair<unsigned char, double>('p', 0.0193),
			std::pair<unsigned char, double>('q', 0.0010),
			std::pair<unsigned char, double>('r', 0.0599),
			std::pair<unsigned char, double>('s', 0.0633),
			std::pair<unsigned char, double>('t', 0.0906),
			std::pair<unsigned char, double>('u', 0.0276),
			std::pair<unsigned char, double>('v', 0.0098),
			std::pair<unsigned char, double>('w', 0.0236),
			std::pair<unsigned char, double>('x', 0.0015),
			std::pair<unsigned char, double>('y', 0.0197),
			std::pair<unsigned char, double>('z', 0.0007)
		};
		/* english characters arranged by statistical frequency in english text */
		alphaByFreq = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', \
			'r', 'd', 'l', 'c', 'u', 'm', 'w', 'f', \
			'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', \
			'q', 'z' };

		/* The only one-letter words in English are */
		monoWdByFreq = { "a", "i" };
		/* you should never find these characters in double */
		neverdouble = {
			'h', 'j', 'q', 'v', 'w', 'x', 'y' };
		/* The most common two-letter words are */
		wd2ByFreq = {
			"of", "to", "in", "it", "is", "be", "as", "at", "so", "we", "he", "by", "or ", "on", "do", "if", "me", "my", "up", "an", "go", "no", "us", "am"
		};

		al2ByFreq = {
			"th", "er", "on", "an", "re", "he", "in", "ed", "nd", "ha", "at", "en", "es", "of", "or", "nt", "ea", "ti", "to", "it", "st", "io", "le", "is", "ou", "ar", "as", "de", "rt", "ve"
		};
		/*In English the most common repeated letters are
		ss, ee, tt, ff, ll, mm and oo. If the ciphertext
		contains any repeated characters, you can assume
		that they represent one of these.
		*/
		al2by2ByFreq = { "ss", "ee", "tt", "ff", "ll", "mm", "oo" };

		wd3ByFreq = { "the", "and", "for", "are", "but", "not", "you", "all", \
			"any", "can", "had", "her", "was", "one", "our", "out", "day", \
			"get", "has", "him", "his", "how", "man", "new", "now", "old", \
			"see", "two", "way", "who", "boy", "did", "its", "let", "put", \
			"say", "she", "too", "use" };

		wd4ByFreq = { "that", "with", "have", "this", "will", "your", \
			"from", "they", "know", "want", "been", "good", "much", "some", \
			"time", "come", "take", "year", "them", "when" };
		VectorWords wbf0 = {};
		vvWordsByFreq.push_back(wbf0);
		vvWordsByFreq.push_back(monoWdByFreq);
		vvWordsByFreq.push_back(wd2ByFreq);
		vvWordsByFreq.push_back(wd3ByFreq);
		vvWordsByFreq.push_back(wd4ByFreq);

	}
	void PrintCharByFreq();
	// construct a vector containing the first N words of size M
	std::vector<std::string> GetFirstNofWordSize(size_t count, size_t wdLen);
	MessageBase::VectorWords GetWordVectorOfLenN(size_t count, size_t wordLen);
};



