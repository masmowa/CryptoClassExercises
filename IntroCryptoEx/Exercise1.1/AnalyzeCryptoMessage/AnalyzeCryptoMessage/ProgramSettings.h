#pragma once
class ProgramSettings
{
protected:
	static bool verbose;
public:
	static bool IsVerbose() { return ProgramSettings::verbose; }

};

