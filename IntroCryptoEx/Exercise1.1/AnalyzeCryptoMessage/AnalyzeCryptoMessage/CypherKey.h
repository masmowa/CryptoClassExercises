#pragma once
#include <iostream>
#include <map>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include"MessageBase.h"
class CypherKey : public MessageBase
{
public:
	typedef std::map<char, char> MapKey;
	// pair CT, PT
	typedef std::pair<char, char> KeyPair;
	MapKey key;
	// hold word strings ct,pt pair
	MapWord mapWordKey;

	CypherKey()
	{
		InitKey();
	}
	CypherKey(const std::string & n) : name(n)
	{
		InitKey();
	}
	void InitKey()
	{
		key = {
			KeyPair('a','?'),
			KeyPair('b','?'),
			KeyPair('c','?'),
			KeyPair('d','?'),
			KeyPair('e','?'),
			KeyPair('f','?'),
			KeyPair('g','?'),
			KeyPair('h','?'),
			KeyPair('i','?'),
			KeyPair('j','?'),
			KeyPair('k','?'),
			KeyPair('l','?'),
			KeyPair('m','?'),
			KeyPair('n','?'),
			KeyPair('o','?'),
			KeyPair('p','?'),
			KeyPair('q','?'),
			KeyPair('r','?'),
			KeyPair('s','?'),
			KeyPair('t','?'),
			KeyPair('u','?'),
			KeyPair('v','?'),
			KeyPair('w','?'),
			KeyPair('x','?'),
			KeyPair('y','?'),
			KeyPair('z','?')
		};

	}
	bool KeyCollision(const std::string& CT, const std::string& PT);
	bool SetKeyValues(const std::string& CT, const std::string& PT);
	bool SetKeyValues(const std::vector<std::string>& CT, const std::vector<std::string>& PT);
	bool SetKeyValuesRev(const std::vector<std::string>& CT, const std::vector<std::string>& PT);
	// send the key contents to std::cout
	void PrintKey();
	// Create a new string with cipher-text replaced by plain-text
	std::string Decipher(const std::string& CT);
	// name to indicate which guess this is
	std::string name;

	void SetName(const std::string& val)
	{
		name = val;
	}
	// match Cyper-Text to Plain-Text based on "frequency" from frequency sorted vectors
	bool SetKeyValuesFromCtCharCount(const MessageBase::VectorCharCount vCT, const std::vector<char>& PT);
	bool KeyHasPtVal(const char guess);
	bool InsertWordKey(const std::string& CT, const std::string& PT);
};

