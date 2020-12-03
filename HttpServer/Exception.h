#pragma once

#include <string>

template <typename ...Args>
std::string __Exception_Combine__(Args&&... args)
{
	std::ostringstream ss;
	(ss << ... << args);
	return ss.str();
}

#define __Exception_ToStringFunc__(x) #x
#define __Exception_ToString__(x) __Exception_ToStringFunc__(x)

#define __Exception_Line__ __Exception_ToString__(__LINE__)

#pragma region public

#define ExceptionThrow(ex, ...) throw ex(__Exception_Combine__(__VA_ARGS__).c_str())

#pragma endregion public
