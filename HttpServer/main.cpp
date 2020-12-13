#include <chrono>

#include "HttpServer.h"
#include "String.h"
#include "CppServerPages.h"

//#define FilterTest
//#define CoffeeTest
#define AccessTest
//#define UserTest

int main(const int argc, char* argv[])
{
	auto lp = KappaJuko::LauncherParams::FromArgs(argc, argv);
	
#ifdef FilterTest
	static std::vector<std::string_view> allow = { "/f", "/k/Library", "/m/Share" };
	//static std::vector<std::string_view> allow = { "\Danbooru2018", "\Library" };
	static std::ostringstream indexPage{};
	indexPage
		<< R"(<!DOCTYPE html>
<html>
	<head>
		<title>Index of /</title>
		<meta charset="utf-8">
		<style type="text/css">
			body {background: #222;color: #ddd;font-family: "Lato", "Hiragino Sans GB", "Source Han Sans SC", "Source Han Sans CN", "Noto Sans CJK SC", "WenQuanYi Zen Hei", "WenQuanYi Micro Hei", "Î¢ÈíÑÅºÚ", sans-serif;}
			a {text-decoration: none;}
			a:link, a:visited {color: #6793cf;}
			a:hover, a:active, a:focus {color: #62bbe7;}
			tr td:nth-child(2) {text-align: right;}
		</style>
		<style type="text/css">
			li {width: 260px;height: 260px;float: left;margin-left: 10px;margin-top: 10px;list-style-type: none;}
			img {max-width: 100%;max-height: 100%;position: relative;left: 50%;top: 50%;transform: translate(-50%, -50%);}
			#preview {background-color: rgba(0, 0, 0, 0.8);width: 100%;height: 100%;position: fixed;top: 0;left: 0;z-index: 100;}
			#preview img {left: 50%;top: 50%;transform: translate(-50%, -50%);position: relative;}
		</style>
		<script type="application/javascript">
			document.onreadystatechange = () =>
				[...document.getElementsByTagName('img')].forEach(x => {
					x.onclick = () => {
						let pv = document.createElement('div');
						pv.id = 'preview';pv.onclick = () => document.getElementById('preview').remove();
						let pic = document.createElement('img');
						pic.src = x.src;
						pv.appendChild(pic);
						[...document.getElementsByTagName('body')].forEach(x => x.appendChild(pv));
					};
				});
		</script>
	</head>
	<body>
		<h1>Index of /</h1><hr>)";
	for (const auto& dir : allow)
	{
		indexPage << "<a href=\"" << dir << "/\">" << dir << "/</a><br>";
	}
	indexPage << "</body></html>";
	static auto index = KappaJuko::Response::FromHtml(indexPage);
	index.Finish();
	lp.CgiHook = [&](KappaJuko::Request& req)
	{
		const auto path = std::filesystem::u8path(req.Path()).lexically_normal().u8string();
		KappaJuko::Log.Write(" [csp]\n", path);
		if (path == "/" || path == "\\")
		{
			index.SendAndClose(req.Client);
			return true;
		}
		const auto pos = std::find_if(allow.begin(), allow.end(), [&](const auto& x) { return path.find(x) == 0; });
		if (pos == allow.end())
		{
			auto toIndex = KappaJuko::Response(302);
			toIndex.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/";
			toIndex.Finish();
			toIndex.SendAndClose(req.Client);
			return true;
		}
		return false;
	};
#endif

#ifdef CoffeeTest
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
		if (req.Path() == "/coffee.cpp")
		{
			coffee.SendAndClose(req.Client);
			return true;
		}
		return false;
	};
#endif

#ifdef AccessTest

#endif

#ifdef UserTest
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

	CppServerPages::Database<std::string, std::string> userDb{};
	userDb.Set("root", "toor");
	userDb.Set("test", "test");
	
	std::unordered_map<std::string, std::function<bool(KappaJuko::Request&)>> route
	{
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
#endif

	KappaJuko::HttpServer server(lp);
	server.Init();
	server.Run();
}
