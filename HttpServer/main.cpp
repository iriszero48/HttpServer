#include <chrono>

#include "HttpServer.h"
#include "String.h"
#include "CppServerPages.h"

int main(const int argc, char* argv[])
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

	std::ostringstream loginPage{};
	loginPage <<
		"<!DOCTYPE html>"
		"<html>"
			"<head>"
				"<title>index</title>"
			"</head>"
			"<body>"
				"<form action=\"\" method=\"POST\">"
					"username:<input type=\"text\" name=\"username\"><br>"
					"password:<input type=\"password\" name=\"password\"><br>"
					"<input type=\"submit\" value=\"login\">"
				"</form>"
			"</body>"
		"</html>";

	std::ostringstream registerPage{};
	registerPage <<
		"<!DOCTYPE html>"
		"<html>"
			"<head>"
				"<title>index</title>"
			"</head>"
			"<body>"
				"<form action=\"\" method=\"POST\">"
					"username:<input type=\"text\" name=\"username\"><br>"
					"password:<input type=\"password\" name=\"password\"><br>"
					"<input type=\"submit\" value=\"register\">"
				"</form>"
			"</body>"
		"</html>";

	std::function<bool(KappaJuko::Request&)> indexCpp = [](KappaJuko::Request& req) -> bool
	{
		const auto sessid = req.Cookie("KJSESSID");
		const auto toLogicWithNewSessid = [&]()
		{
			KappaJuko::Response toLogin(302);
			toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
			const auto newSessid = CppServerPages::GenerateSessionId();
			CppServerPages::Sessions.Set(newSessid, { {}, std::chrono::system_clock::now() });
			std::string ck{};
			String::StringCombine(ck, "KJSESSID=", newSessid, "; HttpOnly");
			toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::SetCookie] = ck;
			toLogin.Finish();
			toLogin.Send(req.Client);
		};
		if (!sessid.has_value())
		{
			toLogicWithNewSessid();
			return true;
		}
		const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
		if (!sessidDb.has_value())
		{
			toLogicWithNewSessid();
			return true;
		}
		if (!sessidDb->User.has_value())
		{
			KappaJuko::Response toLogin(302);
			toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
			toLogin.Finish();
			toLogin.Send(req.Client);
		}
		std::ostringstream boardPage{};
		boardPage <<
			"<!DOCTYPE html>"
			"<html>"
			"<head>"
				"<title>index.cpp</title>"
			"</head>"
				"<body>"
					"<h1>Hello, " << *sessidDb->User << "!</h1>"
				"</body>"
			"</html>";
		auto board = KappaJuko::Response::FromHtml(boardPage);
		board.Finish();
		board.Send(req.Client);
	};

	CppServerPages::Database<std::string, std::string> userDb{};
	userDb.Set("root", "toor");
	userDb.Set("test", "test");
	
	std::unordered_map<std::string, std::function<bool(KappaJuko::Request&)>> route
	{
		{"/coffee.cpp", [&](KappaJuko::Request& req)
		{
			return coffee.SendAndClose(req.Client);
		}},
		{"/login.cpp", [&](KappaJuko::Request& req)
		{
			const auto sessid = req.Cookie("KJSESSID");
			if (req.Method() == KappaJuko::WebUtility::HttpMethod::GET)
			{
				if (sessid.has_value())
				{
					const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
					if (sessidDb.has_value())
					{
						if (sessidDb->User.has_value())
						{
							KappaJuko::Response toLogin(302);
							toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/index.cpp";
							toLogin.Finish();
							toLogin.Send(req.Client);
							return true;
						}
						auto lg = KappaJuko::Response::FromHtml(loginPage);
						lg.Finish();
						lg.Send(req.Client);
						return true;
					}
				}
				auto lg = KappaJuko::Response::FromHtml(loginPage);
				lg.Send(req.Client);
				return true;
			}
			if (req.Method() == KappaJuko::WebUtility::HttpMethod::POST)
			{
				if (sessid.has_value())
				{
					const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
					if (sessidDb.has_value())
					{
						if (sessidDb->User.has_value())
						{
							KappaJuko::Response toLogin(302);
							toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/index.cpp";
							toLogin.Finish();
							toLogin.Send(req.Client);
							return true;
						}
						const auto un = req.Post("username").value_or("");
						const auto pos = userDb.Get(un).value_or("");
						if (!pos.empty() && pos == req.Post("password").value_or(""))
						{
							CppServerPages::Sessions.Set(*sessid, { un, std::chrono::system_clock::now() });
							KappaJuko::Response toLogin(302);
							toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/index.cpp";
							toLogin.Finish();
							toLogin.Send(req.Client);
							return true;
						}
						std::ostringstream errorPage{};
						errorPage <<
							"<!DOCTYPE html>"
							"<html>"
							"<head>"
							"<title>index</title>"
							"</head>"
							"<body>"
							"<h1>Invalid Username/Password!</h1>"
							"</body>"
							"</html>";
						auto error = KappaJuko::Response::FromHtml(errorPage);
						error.Finish();
						error.Send(req.Client);
						return true;
					}
				}
			}
			return false;
		}},
		{"/register.cpp", [&](KappaJuko::Request& req)
		{

			return false;
		}},
		{"/index.cpp", [&](KappaJuko::Request& req)
		{
			const auto sessid = req.Cookie("KJSESSID");
			const auto toLogicWithNewSessid = [&]()
			{
				KappaJuko::Response toLogin(302);
				toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
				const auto newSessid = CppServerPages::GenerateSessionId();
				CppServerPages::Sessions.Set(newSessid, { {}, std::chrono::system_clock::now() });
				std::string ck{};
				String::StringCombine(ck, "KJSESSID=", newSessid, "; HttpOnly");
				toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::SetCookie] = ck;
				toLogin.Finish();
				toLogin.Send(req.Client);
			};
			if (!sessid.has_value())
			{
				toLogicWithNewSessid();
				return true;
			}
			const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
			if (!sessidDb.has_value())
			{
				toLogicWithNewSessid();
				return true;
			}
			if (!sessidDb->User.has_value())
			{
				KappaJuko::Response toLogin(302);
				toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
				toLogin.Finish();
				toLogin.Send(req.Client);
				return true;
			}
			std::ostringstream boardPage{};
			boardPage <<
				"<!DOCTYPE html>"
				"<html>"
				"<head>"
					"<title>index.cpp</title>"
				"</head>"
					"<body>"
						"<h1>Hello, " << *sessidDb->User << "!</h1>"
					"</body>"
				"</html>";
			auto board = KappaJuko::Response::FromHtml(boardPage);
			board.Finish();
			board.Send(req.Client);
			return true;
		}},
	};
	
	lp.CgiHook = [&](KappaJuko::Request& req)
	{
		const auto func = route.find(req.Path());
		if (func != route.end())
		{
			return func->second(req);
		}
		return false;
	};

	KappaJuko::HttpServer server(lp);
	server.Init();
	server.Run();
}
