#include "ProgramSettings.h"
#if defined(DEBUG_VERBOSE)
bool ProgramSettings::verbose = true;
#else
bool ProgramSettings::verbose = false;
#endif