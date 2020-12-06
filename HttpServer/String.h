#pragma once

#include <cctype>
#include <algorithm>

namespace String
{
	template<typename T>
	void ToUpper(T& string)
	{
		std::transform(string.begin(), string.end(), string.begin(), static_cast<int(*)(int)>(std::toupper));
	}

	template<typename T>
	void ToLower(T& string)
	{
		std::transform(string.begin(), string.end(), string.begin(), static_cast<int(*)(int)>(std::tolower));
	}
}
