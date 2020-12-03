#pragma once

#include <string>

namespace Convert
{
	[[nodiscard]] int ToInt(const std::string& value, int base = 10);

	[[nodiscard]] float ToFloat(const std::string& value);

	[[nodiscard]] double ToDouble(const std::string& value);

	[[nodiscard]] std::string ToString(const std::string_view& string);
}