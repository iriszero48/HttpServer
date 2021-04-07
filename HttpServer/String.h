#pragma once

#include <cctype>
#include <algorithm>
#include <string>

namespace String
{
	template<typename Func, typename ...Args>
	std::string NewString(const Func func, Args&&...args)
	{
		std::string buf{};
		func(buf, std::forward<Args>(args)...);
		return buf;
	}


	template<typename Func>
	struct New
	{
		Func Caller;

		explicit New(const Func caller) : Caller(caller) {}

		template<typename T, typename ...Args>
		std::string operator()(const T str, Args&&...args)
		{
			std::string buf(str);
			Caller(buf, std::forward<Args>(args)...);
			return buf;
		}
	};

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

	template<typename...Args>
	void StringCombine(std::string& str, Args&&... args)
	{
		(str.append(args), ...);
	}

	template<typename...Args>
	std::string StringCombineNew(Args&&... args)
	{
		std::string str{};
		(str.append(args), ...);
		return str;
	}

	template<typename T, typename...Args>
	void FromStream(std::string& str, const T& stream, Args&&...fmt)
	{
		std::ostringstream buf{};
		(buf << ... << fmt) << stream;
		str.append(buf.str());
	}

	template<typename T, typename...Args>
	std::string FromStreamNew(const T& stream, Args&&...fmt)
	{
		std::ostringstream buf{};
		(buf << ... << fmt) << stream;
		return buf.str();
	}
}
