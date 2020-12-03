#include "HttpServer.h"
#include <execution>
int main(int argc, char* argv[])
{
	auto lp = KappaJuko::LauncherParams::FromArgs(argc, argv);
	
	std::ostringstream coffeePage{};
	coffeePage
		<< "<html><head><title>418</title></head>"
		<< "<body><h1>Error 418 - I'm a Teapot</h1><br/>"
		<< "You attempt to brew coffee with a teapot.<hr>"
		<< KappaJuko::ServerVersion
		<< "</body></html>";
	auto coffee = KappaJuko::Response::FromHtml(coffeePage, 418);
	coffee.Finish();
	
	lp.CgiHook = [&](KappaJuko::Request& req)
	{
		if (req.Path() == "/coffee")
		{
			coffee.Send(req.Client);
			return true;
		}
		return false;
	};

	KappaJuko::HttpServer server(lp);
	server.Init();
	server.Run();
}
