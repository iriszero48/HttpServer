#include <filesystem>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <regex>

#include "HttpServer.h"
#include "Convert.h"
#include "Function.h"
#include "Exception.h"
#include "Macro.h"

#ifdef __Kappa_Juko__Windows__

#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "User32.lib")

#else

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <csignal>

#endif

#define KappaJukoThrow(ex, ...) ExceptionThrow(ex, __FILE__ ":" MacroLine ":", __VA_ARGS__)

#ifdef __Kappa_Juko__Windows__
#define CloseSocket closesocket
#else
#define CloseSocket close
#endif

namespace KappaJuko
{
#undef DELETE
	ArgumentOptionCpp(NetworkIoModel, Blocking, Multiplexing)
	ArgumentOptionCpp(HttpMethod, GET, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH)
	ArgumentOptionCpp(HttpHeadersKey, Accept, AcceptCH, AcceptCHLifetime, AcceptCharset, AcceptEncoding, AcceptLanguage,
	                  AcceptPatch, AcceptRanges, AccessControlAllowCredentials, AccessControlAllowHeaders,
	                  AccessControlAllowMethods, AccessControlAllowOrigin, AccessControlExposeHeaders,
	                  AccessControlMaxAge, AccessControlRequestHeaders, AccessControlRequestMethod, Age, Allow, AltSvc,
	                  Authorization, CacheControl, ClearSiteData, Connection, ContentDisposition, ContentEncoding,
	                  ContentLanguage, ContentLength, ContentLocation, ContentRange, ContentSecurityPolicy,
	                  ContentSecurityPolicyReportOnly, ContentType, Cookie, CrossOriginEmbedderPolicy,
	                  CrossOriginOpenerPolicy, CrossOriginResourcePolicy, DNT, DPR, Date, DeviceMemory, Digest, ETag,
	                  EarlyData, Expect, ExpectCT, Expires, Forwarded, From, Host, IfMatch, IfModifiedSince,
	                  IfNoneMatch, IfRange, IfUnmodifiedSince, Index, KeepAlive, LastModified, Link, Location, NEL,
	                  Origin, ProxyAuthenticate, ProxyAuthorization, Range, Referer, ReferrerPolicy, RetryAfter,
	                  SaveData, SecFetchDest, SecFetchMode, SecFetchSite, SecFetchUser, SecWebSocketAccept, Server,
	                  ServerTiming, SetCookie, SourceMap, HTTPStrictTransportSecurity, TE, TimingAllowOrigin, Tk,
	                  Trailer, TransferEncoding, UpgradeInsecureRequests, UserAgent, Vary, Via, WWWAuthenticate,
	                  WantDigest, Warning, XContentTypeOptions, XDNSPrefetchControl, XFrameOptions, XXSSProtection)

	static std::string UrlDecode(const std::string& raw)
	{
		std::string res{};
		for (std::string::size_type i = 0, pos; i < raw.length();)
		{
			if ((pos = raw.find('%', i)) == std::string::npos)
			{
				res.append(raw, i);
				break;
			}
			res.append(raw, i, pos - i);
			res.append(1, static_cast<char>(Convert::ToInt(raw.substr(pos + 1, 2), 16)));
			i = pos + 3;
		}
		puts(res.c_str());
		return res;
	}
	
	Request::Request(const SocketType sock, const sockaddr_in& addr): Client(sock), addr(addr)
	{
		int len;
		char buf[4097]{ 0 };
		while ((len = recv(Client, buf, 4096, 0)) == 4096)
		{
			raw.append(buf);
		}
		buf[len] = 0;
		raw.append(buf);
		puts(raw.c_str());
	}
	
	HttpMethod Request::Method()
	{
		if (!method.has_value())
		{
			rawMethod = raw.substr(0, raw.find(' '));
			std::transform(rawMethod.begin(), rawMethod.end(), rawMethod.begin(), static_cast<int(*)(int)>(std::toupper));
			method = ToHttpMethod(rawMethod);
		}
		return method.value();
	}
	
	std::filesystem::path Request::Path()
	{
		if (!path.has_value())
		{
			Method();
			const auto offset = rawMethod.length() + 1;
			rawUrl = raw.substr(offset, raw.find(' ', offset) - offset);
			queryPos = rawUrl.find('?');
			path = UrlDecode(rawUrl.substr(1, queryPos - 1));
		}
		return path.value();
	}
	std::string Request::Header(const std::string& param)
	{
		return headerData.value().at(param);
	}
	std::string Request::Get(const std::string& param)
	{
		return getData.value().at(param);
	}
	std::string Request::Post(const std::string& param)
	{
		return postData.value().at(param);
	}
	Response::Response(const uint16_t statusCode)
	{
		head << HttpVersion << " " << statusCode << " " << HttpStatusCodes[statusCode] << "\r\n";
	}
	Response::Response(const Response& resp)
	{
		SendBody = resp.SendBody;
		Headers = resp.Headers;
		head << resp.head.str();
		headBuf = resp.headBuf;
	}
	Response::Response(Response&& resp) noexcept
	{
		SendBody = resp.SendBody;
		Headers = resp.Headers;
		head << resp.head.str();
		resp.head.clear();
		headBuf = resp.headBuf;
	}

	Response& Response::operator=(const Response& resp)
	{
		SendBody = resp.SendBody;
		Headers = resp.Headers;
		head << resp.head.str();
		headBuf = resp.headBuf;
		return *this;
	}
	
	Response& Response::operator=(Response&& resp) noexcept
	{
		SendBody = resp.SendBody;
		Headers = resp.Headers;
		head << resp.head.str();
		headBuf = resp.headBuf;
		return *this;
	}

	void Response::Finish()
	{
		for (const auto& [key, value] : Headers)
		{
			head << HttpHeaders[key] << ": " << value << "\r\n";
		}
		head << "\r\n";
		headBuf = head.str();
	}

	bool Response::Send(const SocketType client)
	{
		send(client, headBuf.c_str(), headBuf.length(), 0);
		puts(headBuf.c_str());
		if (SendBody.has_value())
		{
			SendBody.value()(client);
		}
		return true;
	}

	bool Response::SendAndClose(const SocketType client)
	{
		Send(client);
		CloseSocket(client);
		return true;
	}

	Response Response::FromStatusCode(const uint16_t statusCode)
	{
		std::ostringstream page{};
		page
			<< "<html><head><title>" << statusCode << "</title></head>"
			<< "<body><h1>" << statusCode << " - " << HttpStatusCodes[statusCode] << "</h1><br/><hr>"
			<< ServerVersion
			<< "</body></html>";
		auto resp = FromHtml(page, statusCode);
		resp.Finish();
		return resp;
	}
	
	Response Response::FromHtml(const std::ostringstream& html, const uint16_t statusCode)
	{
		const auto buf = html.str();
		Response resp(statusCode);
		resp.Headers[HttpHeadersKey::ContentLength] = std::to_string(buf.length());
		resp.Headers[HttpHeadersKey::Connection] = "Close";
		resp.SendBody = [=](auto client)
		{
			send(client, buf.c_str(), buf.length(), 0);
		};
		return resp;
	}
	
	Response Response::FromFile(const std::filesystem::path& path, const uint16_t statusCode)
	{
		Response resp(statusCode);
		resp.Headers[HttpHeadersKey::ContentLength] = std::to_string(file_size(path));
		resp.SendBody = [&](auto client)
		{
			std::ifstream fs(path, std::ios_base::in | std::ios_base::binary);
			char buf[4096];
			do
			{
				fs.read(buf, 4096);
				send(client, buf, fs.gcount(), 0);
			}
			while (!fs.eof());
		};
		return resp;
	}

	LauncherParams LauncherParams::FromArgs(const int _args, char** _argv)
	{
		using ArgumentsParse::Arguments;
		using ArgumentsParse::Argument;
		using Function::Compose;
		Arguments args{};
#define ArgumentsFunc(arg) [](decltype(arg)::ConvertFuncParamType value) -> decltype(arg)::ConvertResult
#define ArgumentsValue(arg) args.Value<decltype(arg)::ValueType>(arg)
		Argument<std::string_view> rootPath
		{
			"",
			"root path"
		};
		Argument<uint16_t> port
		{
			"-p",
			"port(80)",
			80,
			ArgumentsFunc(port)
			{
				return {
					static_cast<uint16_t>(Compose(Convert::ToString,
					                              std::bind(Convert::ToInt, std::placeholders::_1, 10))(value)),
					{}
				};
			}
		};
		Argument<uint16_t> threadCount
		{
			"-t",
			"work thread count(1)",
			1,
			ArgumentsFunc(threadCount)
			{
				return {
					static_cast<uint16_t>(Compose(Convert::ToString,
					                              std::bind(Convert::ToInt, std::placeholders::_1, 10))(value)),
					{}
				};
			}
		};
		Argument<NetworkIoModel> ioModel
		{
			"--iomodel",
			"network IO model " + NetworkIoModelDesc(ToString(NetworkIoModel::Multiplexing)),
			NetworkIoModel::Multiplexing,
			ArgumentsFunc(ioModel)
			{
				return {Compose(Convert::ToString, ToNetworkIoModel)(value), {}};
			}
		};
		Argument<bool, 0> autoIndexMode
		{
			"--autoindex",
			"auto index mode",
			false,
			ArgumentsFunc(autoIndexMode)
			{
				return {true, {}};
			}
		};
		Argument<bool, 0> notFoundRedirect
		{
			"--redirect",
			"not found redirect",
			false,
			ArgumentsFunc(notFoundRedirect)
			{
				return {true, {}};
			}
		};
		Argument<std::string_view> charset
		{
			"--charset",
			"charset(utf-8)",
			"utf-8"
		};
		Argument<Response> notFoundResponse
		{
			"--404",
			"404 page",
			Response::FromStatusCode(404),
			ArgumentsFunc(notFoundResponse)
			{
				auto resp = Response::FromFile(Convert::ToString(value), 404);
				resp.Finish();
				return {resp, {}};
			}
		};
		Argument<Response> forbiddenResponse
		{
			"--403",
			"403 page",
			Response::FromStatusCode(403),
			ArgumentsFunc(forbiddenResponse)
			{
				auto resp = Response::FromFile(Convert::ToString(value), 403);
				resp.Finish();
				return {resp, {}};
			}
		};
		Argument<std::vector<std::string_view>> indexPages
		{
			"--indexPages",
			"index pages",
			{
				{ "index.html" }
			},
			ArgumentsFunc(indexPages)
			{
				std::vector<std::string_view> res{};
				auto pos = value.find(',');
				decltype(pos) i = 0;
				while (pos != std::string_view::npos)
				{
					res.push_back(value.substr(i, pos - i));
					i = pos;
				}
				res.push_back(value.substr(i));
				return {res, {}};
			}
		};
		args.Add(rootPath);
		args.Add(port);
		args.Add(threadCount);
		args.Add(ioModel);
		args.Add(autoIndexMode);
		args.Add(notFoundRedirect);
		args.Add(charset);
		args.Add(notFoundResponse);
		args.Add(forbiddenResponse);
		args.Add(indexPages);
		try
		{
			args.Parse(_args, _argv);
			return
			{
				ArgumentsValue(rootPath),
				ArgumentsValue(port),
				ArgumentsValue(threadCount),
				ArgumentsValue(ioModel),
				ArgumentsValue(autoIndexMode),
				ArgumentsValue(notFoundRedirect),
				ArgumentsValue(charset),
				ArgumentsValue(notFoundResponse),
				ArgumentsValue(forbiddenResponse),
				ArgumentsValue(indexPages)
			};
		}
		catch (const std::exception& ex)
		{
			fputs(ex.what(), stderr);
			puts("");
			puts(_argv[0]);
			puts(args.GetDesc().c_str());
			exit(EXIT_FAILURE);
		}
	}
	
	void HttpServer::Init()
	{
#ifdef __Kappa_Juko__Windows__
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			KappaJukoThrow(InitializationException, "WinSock init fail");
		}
#else
		struct sigaction action;
		action.sa_handler = [](int) {};
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		sigaction(SIGPIPE, &action, nullptr);
#endif
		
		serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		
		if (serverSocket
#ifdef __Kappa_Juko__Windows__
			== INVALID_SOCKET
#else
			== -1
#endif
		)
		{
			KappaJukoThrow(CreateSocketException, "Can't create socket");
		}
		
		char optVal[4] = {0};
		setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, optVal, sizeof optVal);
		
		sockaddr_in serverSockAddr{};
		serverSockAddr.sin_family = AF_INET;
		serverSockAddr.sin_addr.s_addr = INADDR_ANY;
		serverSockAddr.sin_port = htons(params.Port);
		if (bind(serverSocket, reinterpret_cast<const sockaddr*>(&serverSockAddr), sizeof serverSockAddr) < 0)
		{
			KappaJukoThrow(BindPortException, "Can't bind port" );
		}
		listen(serverSocket, 10000);
	}
	
	void HttpServer::Run()
	{
		if (params.IoModel == NetworkIoModel::Blocking)
		{
			threadPool = std::vector<std::thread>();
			for (auto i = 0; i < params.ThreadCount; ++i)
			{
				threadPool.emplace_back([&](const auto id)
				{
					while (true)
					{
						sockaddr_in clientAddr{};
						int addrLen = sizeof clientAddr;
						const auto client = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
						if (client <= 0)
						{
							continue;
						}
						try
						{
							Work(client, clientAddr);
						}
						catch (const std::exception& ex)
						{
							std::ostringstream oss{};
							std::regex re("::");
							oss
								<< "Exception in thread \"" << id << "\" java.lang.NullPointerException: " << ex.what() << "\n"
								<< "    at " <<  std::regex_replace(__FUNCTION__, re, ".") << "(" << __FILE__ << ":" << MacroLine << ")" << "\n";
							std::cerr << oss.str();
						}
					}
				}, i);
			}
		}
		for (auto& thread : threadPool)
		{
			thread.join();
		}
	}
	
	void HttpServer::Close() const
	{
		CloseSocket(serverSocket);
	}
	
	bool HttpServer::Work(const SocketType client, const sockaddr_in& address)
	{
		Request req(client, address);
		if (params.CgiHook.has_value())
		{
			if (params.CgiHook.value()(req))
			{
				return true;
			}
		}
		auto realPath = params.RootPath / req.Path();
		switch (req.Method())
		{
		case HttpMethod::GET:
		case HttpMethod::POST:
			if (exists(realPath))
			{
				if (is_directory(realPath))
				{
					const auto pos = std::find_if(
						params.IndexPages.begin(),
						params.IndexPages.end(),
						[&](const auto& index) { return exists(realPath / index); });
					if (pos == params.IndexPages.end())
					{
						if (params.AutoIndexMode)
						{

						}
						params.ForbiddenResponse.SendAndClose(client);
						return true;
					}
					realPath /= *pos;
				}
				if (is_regular_file(realPath))
				{
					auto resp = Response::FromFile(realPath);
					resp.Finish();
					resp.SendAndClose(req.Client);
					return true;
				}
				params.ForbiddenResponse.SendAndClose(client);
				return true;
			}
			params.NotFoundResponse.SendAndClose(client);
			return true;
		case HttpMethod::PUT:
		case HttpMethod::DELETE:
		case HttpMethod::CONNECT:
		case HttpMethod::OPTIONS:
		case HttpMethod::TRACE:
		case HttpMethod::PATCH:
			Response::FromStatusCode(501).SendAndClose(client);
			return true;
		}
		return false;
	}
}
