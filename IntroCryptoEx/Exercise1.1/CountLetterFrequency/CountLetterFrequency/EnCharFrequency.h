#pragma once
#include <iostream>
#include <map>

class EnCharFrequency
{
public:
	typedef std::map<char, double> CharToFreqMap;
	CharToFreqMap ctf;
	EnCharFrequency()
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
	}
};

