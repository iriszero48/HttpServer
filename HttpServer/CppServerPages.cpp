#include "CppServerPages.h"

#include <random>

#include "Convert.h"

namespace CppServerPages
{
	std::string GenerateSessionId()
	{
		static std::random_device rd{};
		static std::uniform_int_distribution<std::uint64_t> dis(0);
		auto buf = Convert::ToString(dis(rd), 16);
		buf.append("-");
		buf.append(Convert::ToString(dis(rd), 16));
		return buf;
	}
}
