#include <iostream>
#include <algorithm>
#include <functional>

#include "HttpServer.h"

int main(int argc, char* argv[])
{
	const auto lp = KappaJuko::LauncherParams::FromArgs(argc, argv);
	KappaJuko::HttpServer server(lp);
	//server.Init();
	//server.Run();
}
