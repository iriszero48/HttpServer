#include <filesystem>
#include <unordered_map>
#include <iostream>
#include <fstream>

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
			path = rawUrl.substr(0, queryPos);
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
		if (SendBody.has_value())
		{
			SendBody.value()(client);
		}
		return true;
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
			char buf[4096]{ 0 };
			std::ifstream fs(path);
			fs.read(buf, 4096);
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
		std::ostringstream defaultNotFoundResponsePage{};
		defaultNotFoundResponsePage
			<< "<html><head><title>404</title></head>"
			<< "<body><h1>Error 404 - " << HttpStatusCodes[404] << "</h1><br/><hr>"
			<< ServerVersion
			<< "</body></html>";
		auto defaultNotFoundResponse = Response::FromHtml(defaultNotFoundResponsePage, 404);
		defaultNotFoundResponse.Finish();
		Argument<Response> notFoundResponse
		{
			"--404page",
			"404 page",
			defaultNotFoundResponse,
			ArgumentsFunc(notFoundResponse)
			{
				auto resp = Response::FromFile(Convert::ToString(value), 404);
				resp.Finish();
				return { resp, {}};
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
				ArgumentsValue(notFoundResponse)
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
							fputs(ex.what(), stderr);
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
		const auto realPath = params.RootPath / req.Path();
		switch (req.Method())
		{
		case HttpMethod::GET:
		case HttpMethod::POST:
			if (exists(realPath))
			{
				if (is_regular_file(realPath))
				{
					auto resp = Response::FromFile(realPath);
					resp.Finish();
					resp.Send(req.Client);
					CloseSocket(client);
					return true;
				}
				if (params.AutoIndexMode && is_directory(realPath))
				{
					
				}
			}
			params.NotFoundResponse.Send(client);
			CloseSocket(client);
			return true;
		case HttpMethod::PUT:
		case HttpMethod::DELETE:
		case HttpMethod::CONNECT:
		case HttpMethod::OPTIONS:
		case HttpMethod::TRACE:
		case HttpMethod::PATCH:
			std::ostringstream notImplPage{};
			notImplPage
				<< "<html><head><title>501</title></head>"
				<< "<body><h1>Error 501 - " << HttpStatusCodes[501] << "</h1><br/><hr>"
				<< ServerVersion
				<< "</body></html>";
			auto notImpl = Response::FromHtml(notImplPage, 501);
			notImpl.Finish();
			notImpl.Send(client);
			return true;
		}
		return false;
	}
}
