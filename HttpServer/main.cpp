#include <atomic>

#include "HttpServer.h"
#include "String.h"
#include "CppServerPages.h"
#include "Exception.h"

//#define FilterTest
//#define CoffeeTest
//#define AccessTest
#define UserTest
//#define OnlineRegexText
//#define RandomTest

#define IfFalseReturnFalse(x) if (!(x)) { return false; }
#define CspThrow(ex, ...) ExceptionThrow(ex, __VA_ARGS__, "\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")")

#ifdef FilterTest

static auto PageResp(const std::string& page, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	auto resp = KappaJuko::Response::FromHtml(keepAlive, page, sendFunc, sendFuncArgs, 200);
	resp.Finish();
	return resp;
};

static auto LocalResp(const std::string& url, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	auto resp = KappaJuko::Response(keepAlive, sendFunc, sendFuncArgs, 302);
	resp.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = url;
	resp.Finish();
	return resp;
};

static const std::vector<std::string_view> Allow =
{
#ifdef MacroWindows
		"\\Danbooru2018", "\\Library"
#else
		"/f", "/k/Library", "/m/Share"
#endif
};

static const auto IndexPage = []()
{
	std::string page =
		R"(<!DOCTYPE html>
<html>
	<head>
		<title>Index of /</title>
		<meta charset="utf-8">
		<style type="text/css">
			body {background: #222;color: #ddd;font-family: "Lato", "Hiragino Sans GB", "Source Han Sans SC", "Source Han Sans CN", "Noto Sans CJK SC", "WenQuanYi Zen Hei", "WenQuanYi Micro Hei", "微软雅黑", sans-serif;}
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
	for (const auto& dir : Allow)
	{
		String::StringCombine(page, "<a href=\"", dir, "/\">", dir, "/</a><br>");
	}
	String::StringCombine(page, "</body></html>");
	return page;
}();

static auto CgiFunc(KappaJuko::Request& req, const decltype(KappaJuko::Response::SendFunc) sendFunc, 
	const std::any& sendFuncArgs, const bool keepAlive, const KappaJuko::LauncherParams& params) -> std::optional<bool>
{
	try
	{
		const auto path = std::filesystem::u8path(req.Path()).lexically_normal().u8string();
		if (path == "/" || path == "\\")
		{
			IfFalseReturnFalse(PageResp(IndexPage, keepAlive, sendFunc, sendFuncArgs).Send(req.Client))
				return keepAlive;
		}
		auto found = false;
		const auto end = Allow.end();
		for (auto pos = Allow.begin(); pos != end; ++pos)
		{
			if (path.find(*pos) == 0)
			{
				found = true;
				break;
			}
		}
		if (!found)
		{
			IfFalseReturnFalse(LocalResp("/", keepAlive, sendFunc, sendFuncArgs).Send(req.Client))
				return keepAlive;
		}
		return std::nullopt;
	}
	catch (const std::exception& ex)
	{
		CspThrow(CppServerPages::CppServerPagesException, ex.what(), " in Filter.csp");
	}
};

#endif

#ifdef UserTest

static std::string loginPage =
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
				"<a href=\"register.cpp\">register</a>"
			"</form>"
		"</body>"
	"</html>";

static std::string registerPage =
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

static CppServerPages::Database<std::string, std::string> userDb{};

bool ToLogin(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	auto lg = KappaJuko::Response::FromHtml(keepAlive, loginPage, sendFunc, sendFuncArgs);
	lg.Finish();
	IfFalseReturnFalse(lg.Send(req.Client))
		return keepAlive;
}

bool RedToLogin(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	KappaJuko::Response toLogin(keepAlive, sendFunc, sendFuncArgs, 302);
	toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
	toLogin.Finish();
	IfFalseReturnFalse(toLogin.Send(req.Client))
		return keepAlive;
}

bool RedToIndex(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	KappaJuko::Response toLogin(keepAlive, sendFunc, sendFuncArgs, 302);
	toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/index.cpp";
	toLogin.Finish();
	IfFalseReturnFalse(toLogin.Send(req.Client))
		return keepAlive;
}

bool Login(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
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
					return RedToIndex(req, keepAlive, sendFunc, sendFuncArgs);
				}
				return ToLogin(req, keepAlive, sendFunc, sendFuncArgs);
			}
		}
		return ToLogin(req, keepAlive, sendFunc, sendFuncArgs);
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
					return RedToIndex(req, keepAlive, sendFunc, sendFuncArgs);
				}
				const auto un = req.Post("username").value_or("");
				const auto pos = userDb.Get(un).value_or("");
				if (!pos.empty() && pos == req.Post("password").value_or(""))
				{
					CppServerPages::Sessions.Set(*sessid, { un, std::chrono::system_clock::now() });
					return RedToIndex(req, keepAlive, sendFunc, sendFuncArgs);
				}
				std::string errorPage =
					"<!DOCTYPE html>"
					"<html>"
						"<head>"
							"<title>index</title>"
						"</head>"
						"<body>"
							"<h1>Invalid Username/Password!</h1>"
						"</body>"
					"</html>";
				auto error = KappaJuko::Response::FromHtml(keepAlive, errorPage, sendFunc, sendFuncArgs);
				error.Finish();
				IfFalseReturnFalse(error.Send(req.Client))
				return keepAlive;
			}
		}
	}
	return keepAlive;
}

bool RedToRegister(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	KappaJuko::Response toLogin(keepAlive, sendFunc, sendFuncArgs, 302);
	toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/register.cpp";
	toLogin.Finish();
	IfFalseReturnFalse(toLogin.Send(req.Client))
		return keepAlive;
}

bool Register(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	if (req.Method() == KappaJuko::WebUtility::HttpMethod::GET)
	{
		auto lg = KappaJuko::Response::FromHtml(keepAlive, registerPage, sendFunc, sendFuncArgs);
		lg.Finish();
		IfFalseReturnFalse(lg.Send(req.Client))
			return keepAlive;
	}
	if (req.Method() == KappaJuko::WebUtility::HttpMethod::POST)
	{
		const auto un = req.Post("username").value_or("");
		const auto pos = userDb.Get(un).value_or("");
		if (pos.empty())
		{
			const auto pw = req.Post("password").value_or("");
			if (!pw.empty())
			{
				userDb.Set(un, pw);
				std::string succeedPage =
					"<!DOCTYPE html>"
					"<html>"
					"<head>"
					"<title>Register</title>"
					"</head>"
					"<body>"
					"<h1>Register succeed!</h1>"
					"</body>"
					"</html>";
				auto succ = KappaJuko::Response::FromHtml(keepAlive, succeedPage, sendFunc, sendFuncArgs);
				succ.Finish();
				IfFalseReturnFalse(succ.Send(req.Client))
					return keepAlive;
			}
			std::string errorPage =
				"<!DOCTYPE html>"
				"<html>"
				"<head>"
				"<title>Error</title>"
				"</head>"
				"<body>"
				"<h1>java.lang.NullPointerException</h1>"
				"</body>"
				"</html>";
			auto error = KappaJuko::Response::FromHtml(keepAlive, errorPage, sendFunc, sendFuncArgs);
			error.Finish();
			IfFalseReturnFalse(error.Send(req.Client))
				return keepAlive;
		}
		std::string errorPage =
			"<!DOCTYPE html>"
			"<html>"
				"<head>"
					"<title>Error</title>"
				"</head>"
				"<body>"
					"<h1>Username Existed!</h1>"
				"</body>"
			"</html>";
		auto error = KappaJuko::Response::FromHtml(keepAlive, errorPage, sendFunc, sendFuncArgs);
		error.Finish();
		IfFalseReturnFalse(error.Send(req.Client))
			return keepAlive;
	}
	return keepAlive;
}

bool ToLogicWithNewSessid(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	KappaJuko::Response toLogin(keepAlive, sendFunc, sendFuncArgs, 302);
	toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::Location] = "/login.cpp";
	const auto newSessid = CppServerPages::GenerateSessionId();
	CppServerPages::Sessions.Set(newSessid, { {}, std::chrono::system_clock::now() });
	std::string ck{};
	String::StringCombine(ck, "KJSESSID=", newSessid, "; HttpOnly");
	toLogin.Headers[KappaJuko::WebUtility::HttpHeadersKey::SetCookie] = ck;
	toLogin.Finish();
	IfFalseReturnFalse(toLogin.Send(req.Client))
		return keepAlive;
};

bool Index(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	const auto sessid = req.Cookie("KJSESSID");
	if (!sessid.has_value())
	{
		return ToLogicWithNewSessid(req, keepAlive, sendFunc, sendFuncArgs);
	}
	const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
	if (!sessidDb.has_value())
	{
		return ToLogicWithNewSessid(req, keepAlive, sendFunc, sendFuncArgs);
	}
	if (!sessidDb->User.has_value())
	{
		return RedToLogin(req, keepAlive, sendFunc, sendFuncArgs);
	}
	std::string boardPage{};
	String::StringCombine(boardPage,
		"<!DOCTYPE html>"
		"<html>"
			"<head>"
				"<title>index.cpp</title>"
			"</head>"
			"<body>"
				"<h1>Hello, ", *sessidDb->User, "!</h1>"
				"<a href=\"logout.cpp\">logout</a>"
			"</body>"
		"</html>");
	auto board = KappaJuko::Response::FromHtml(keepAlive, boardPage, sendFunc, sendFuncArgs);
	board.Finish();
	IfFalseReturnFalse(board.Send(req.Client))
		return keepAlive;
}

bool Logout(KappaJuko::Request& req, const bool keepAlive, const decltype(KappaJuko::Response::SendFunc) sendFunc, const std::any& sendFuncArgs)
{
	const auto sessid = req.Cookie("KJSESSID");
	if (!sessid.has_value())
	{
		return ToLogicWithNewSessid(req, keepAlive, sendFunc, sendFuncArgs);
	}
	const auto sessidDb = CppServerPages::Sessions.Get(*sessid);
	if (!sessidDb.has_value())
	{
		return ToLogicWithNewSessid(req, keepAlive, sendFunc, sendFuncArgs);
	}
	if (!sessidDb->User.has_value())
	{
		return RedToIndex(req, keepAlive, sendFunc, sendFuncArgs);
	}
	CppServerPages::Sessions.Set(*sessid, { {}, std::chrono::system_clock::now() });
	std::string boardPage =
		"<!DOCTYPE html>"
		"<html>"
		"<head>"
		"<title>logout.cpp</title>"
		"</head>"
		"<body>"
		"<h1>logout!</h1>"
		"</body>"
		"</html>";
	auto board = KappaJuko::Response::FromHtml(keepAlive, boardPage, sendFunc, sendFuncArgs);
	board.Finish();
	IfFalseReturnFalse(board.Send(req.Client))
		return keepAlive;
}

static std::unordered_map<std::string, bool(*)(KappaJuko::Request&, bool, decltype(KappaJuko::Response::SendFunc), const std::any&)> route
{
	{"/login.cpp", Login},
	{"/register.cpp", Register},
	{"/index.cpp", Index},
	{"/logout.cpp", Logout},
	{"/", Index},
};

static auto CgiFunc(KappaJuko::Request& req, const decltype(KappaJuko::Response::SendFunc) sendFunc,
	const std::any& sendFuncArgs, const bool keepAlive, const KappaJuko::LauncherParams& params) -> std::optional<bool>
{
	try
	{
		const auto func = route.find(req.Path());
		if (func != route.end())
		{
			return func->second(req, keepAlive, sendFunc, sendFuncArgs);
		}
		return std::nullopt;
	}
	catch (const std::exception& ex)
	{
		CspThrow(CppServerPages::CppServerPagesException, ex.what(), " in Filter.csp");
	}
};


#endif

int main(const int argc, char* argv[])
{
	auto lp = KappaJuko::LauncherParams::FromArgs(argc, argv);
#ifdef FilterTest
	lp.CgiHook = CgiFunc;
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
	userDb.Set("root", "toor");
	userDb.Set("test", "test");
	lp.CgiHook = CgiFunc;
#endif

#ifdef RandomTest
	
#endif
	
	KappaJuko::HttpServer server(lp);
	server.Init();
	try
	{
		server.Run();
	}
	catch (const std::exception& ex)
	{
		while (KappaJuko::Log.Chan.Length() != 0)
		{
			using namespace std::chrono_literals;
			std::this_thread::sleep_for(+1s);
		}
		fputs(ex.what(), stderr);
	}
}
