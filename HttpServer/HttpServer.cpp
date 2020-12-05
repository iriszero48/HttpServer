#include <filesystem>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <queue>
#include <list>

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
	namespace WebUtility
	{
		ArgumentOptionCpp(NetworkIoModel, Blocking, Multiplexing)
#undef DELETE
		ArgumentOptionCpp(HttpMethod, GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH)
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
		
		std::string UrlDecode(const std::string& raw)
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
		
		std::string UrlEncode(const std::string& raw)
		{
			std::string res{};
			auto i = std::string::npos;
			while (true)
			{
				i++;
				auto beg = raw.begin();
				std::advance(beg, i);
				auto pos =
					std::find_if(
						beg,
						raw.end(),
						[&](const auto& x) { return UrlEncodeTable[static_cast<uint8_t>(x)]; });
				if (pos == raw.end())
				{
					res.append(raw, i);
					break;
				}
				const auto dis = std::distance(beg, pos);
				res.append(raw, i, dis);
				res.append("%");
				res.append(Convert::ToString(static_cast<uint64_t>(*pos), 16));
				i += dis;
			}
			return res;
		}
	}
	
	Request::Request(const SocketType sock, const sockaddr_in& addr): Client(sock), addr(addr)
	{
		int len;
		char buf[4097] = { 0 };
		do
		{
			len = recv(Client, buf, 4096, 0);
			buf[len] = 0;
			Raw.append(buf);
		}
		while (len == 4096);
		puts(Raw.c_str());
	}

	WebUtility::HttpMethod Request::Method()
	{
		if (!method.has_value())
		{
			rawMethod = Raw.substr(0, Raw.find(' '));
			std::transform(rawMethod.begin(), rawMethod.end(), rawMethod.begin(), static_cast<int(*)(int)>(std::toupper));
			method = WebUtility::ToHttpMethod(rawMethod);
		}
		return method.value();
	}
	
	std::string Request::Path()
	{
		if (!path.has_value())
		{
			Method();
			const auto offset = rawMethod.length() + 1;
			rawUrl = Raw.substr(offset, Raw.find(' ', offset) - offset);
			queryPos = rawUrl.find('?');
			path = WebUtility::UrlDecode(rawUrl.substr(0, queryPos));
		}
		return path.value();
	}
	std::optional<std::string> Request::Header(const WebUtility::HttpHeadersKey& param)
	{
		if (!headerData.has_value())
		{
			headerData = std::map<WebUtility::HttpHeadersKey, std::string>{};
			auto next = Raw.find('\n');
			do
			{
				next++;
				const auto pos = Raw.find(':', next);
				if (pos == std::string::npos)
				{
					break;
				}
				const auto keyStr = Raw.substr(next, pos - next);
				auto key =
					std::find_if(
						WebUtility::HttpHeaders.begin(),
						WebUtility::HttpHeaders.end(),
						[&](const auto& p) { return p.second == keyStr; });
				
				if (key != WebUtility::HttpHeaders.end())
				{
					next = Raw.find('\n', pos);
					headerData.value()[key->first] = Raw.substr(pos + 2, next - pos - 3);
				}
			} while (next != std::string::npos);
		}
		const auto pos = headerData.value().find(param);
		if (pos == headerData.value().end())
		{
			return std::nullopt;
		}
		return pos->second;
	}
	std::optional<std::string> Request::Get(const std::string& param)
	{
		return getData.value().at(param);
	}
	std::optional<std::string> Request::Post(const std::string& param)
	{
		return postData.value().at(param);
	}
	Response::Response(const uint16_t statusCode)
	{
		head << HttpVersion << " " << statusCode << " " << WebUtility::HttpStatusCodes[statusCode] << "\r\n";
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
			head << WebUtility::HttpHeaders[key] << ": " << value << "\r\n";
		}
		head << "\r\n";
		headBuf = head.str();
	}
	
	bool Response::SendHead(const SocketType client) const
	{
		send(client, headBuf.c_str(), headBuf.length(), 0);
		puts(headBuf.c_str());
		return true;
	}

	bool Response::Send(const SocketType client, const bool headOnly)
	{
		SendHead(client);
		if (!headOnly)
		{
			if (SendBody.has_value())
			{
				SendBody.value()(client);
			}
		}
		return true;
	}

	bool Response::SendAndClose(const SocketType client, const bool headOnly)
	{
		Send(client, headOnly);
		CloseSocket(client);
		return true;
	}

	Response Response::FromStatusCode(const uint16_t statusCode)
	{
		std::ostringstream page{};
		page
			<< "<html><head><title>" << statusCode << "</title></head>"
			<< "<body><h1>" << statusCode << " - " << WebUtility::HttpStatusCodes[statusCode] << "</h1><br/><hr>"
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
		resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(buf.length());
		resp.SendBody = [=](const auto client)
		{
			send(client, buf.c_str(), buf.length(), 0);
		};
		return resp;
	}
	
	Response Response::FromFile(const std::filesystem::path& path, const uint16_t statusCode)
	{
		Response resp(statusCode);
		resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(file_size(path));
		resp.SendBody = [&](const auto client)
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
		Argument<std::filesystem::path> rootPath
		{
			"",
			"host:path,...(:80:.)",
			":80:."
		};
		Argument<std::unordered_map<std::string_view, std::filesystem::path>> services
		{
			"",
			"host:path,...(:.)",
			{ { { {}, "." } } },
			ArgumentsFunc(services)
			{
				std::unordered_map<std::string_view, std::filesystem::path> res{};
				auto comPos = std::string_view::npos;
				while (true)
				{
					comPos++;
					auto spPos = value.find(':', comPos);
					const auto host = value.substr(comPos, spPos - comPos);
					spPos++;
					comPos = value.find(',', spPos);
					std::filesystem::path path;
					if (comPos == std::string_view::npos)
					{
						res.emplace(host, value.substr(spPos));
						return { res, {} };
					}
					res.emplace(host, value.substr(spPos, comPos - spPos));
				}
			}
		};
		Argument<uint16_t> port
		{
			"-p",
			"port(80)",
			80,
			ArgumentsFunc(port)
			{
				return {
					static_cast<uint16_t>(Compose([](const auto& x) { return std::string(x); },
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
					static_cast<uint16_t>(Compose([](const auto& x) { return std::string(x); },
					                              std::bind(Convert::ToInt, std::placeholders::_1, 10))(value)),
					{}
				};
			}
		};
		Argument<WebUtility::NetworkIoModel> ioModel
		{
			"--iomodel",
			"network IO model " + WebUtility::NetworkIoModelDesc(WebUtility::ToString(WebUtility::NetworkIoModel::Multiplexing)),
			WebUtility::NetworkIoModel::Multiplexing,
			ArgumentsFunc(ioModel)
			{
				return {Compose([](const auto& x) { return std::string(x); }, WebUtility::ToNetworkIoModel)(value), {}};
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
		//Argument<std::string_view> charset
		//{
		//	"--charset",
		//	"charset(utf-8)",
		//	"utf-8"
		//};
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
			"index pages(index.html,index.htm)",
			{
				{ "index.html", "index.htm" }
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
		//args.Add(charset);
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
				//ArgumentsValue(charset),
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
		if (params.IoModel == WebUtility::NetworkIoModel::Blocking)
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
						catch (const KappaJukoException& ex)
						{
							std::cerr
								<< "Exception in thread \"" << id << "\" java.lang.NullPointerException: " << ex.what() << "\n"
								<< "    at " <<  __FUNCTION__ << "(" << __FILE__ << ":" << MacroLine << ")" << "\n";
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
	
	bool HttpServer::IndexOfResponse(const std::filesystem::path& path, Request& request, SocketType client,
		bool headOnly)
	{
		const auto indexOfPath = request.Path();
		std::ostringstream indexOfPage{};
		indexOfPage <<
			"<!DOCTYPE html>"
			"<html>"
			"<head><title>Index of " << indexOfPath << "</title>"
			"<meta charset=\"utf-8\"/>"
			"</head>"
			"<body>"
			"<h1>Index of " << indexOfPath << "</h1><hr>";

		//                        filename_utf8 filename_urlencoded 
		using DirType = std::tuple<std::string, std::string>;
		using FileType = std::tuple<std::string, std::string, uint64_t>;
		std::priority_queue<DirType, std::vector<DirType>, std::greater<>> dirs;
		std::priority_queue<FileType, std::vector<FileType>, std::greater<>> files;

		
		std::error_code errorCode;
		const std::error_code nonErrorCode;
		const std::filesystem::directory_iterator end;
		for (std::filesystem::directory_iterator file(path, std::filesystem::directory_options::none, errorCode); file != end; ++file)
		{
			if (errorCode != nonErrorCode)
			{
				params.ForbiddenResponse.SendAndClose(client);
				//LogErr(file->path().native().c_str(), errorCode.message().c_str());
				errorCode.clear();
				return true;
			}
			const auto fnu8 = file->path().filename().u8string();
			const auto fn = WebUtility::UrlEncode(fnu8);
			if (file->is_regular_file())
			{
				files.emplace(fnu8, fn, file->file_size());
			}
			else if (file->is_directory())
			{
				dirs.emplace(fnu8, fn);
			}
		}
		
		indexOfPage << "<a href=\"../\">../</a><br/>";
		while (!dirs.empty())
		{
			const auto& [fnu8, fn] = dirs.top();
			indexOfPage << "<a href=\"" << fn << "/\">" << fnu8 << "/</a><br/>";
			dirs.pop();
		}
		indexOfPage << "<hr>";
		if (!files.empty())
		{
			indexOfPage <<
				"<table>"
				"<tr><th>File Name</th><th>Size</th></tr>";
			while (!files.empty())
			{
				const auto& [fnu8, fn, sz] = files.top();
				indexOfPage << "<tr><td><a href=\"" << fn << "\">" << fnu8 << "</a></td><td align=\"right\">" << sz << "</td></tr>";
				files.pop();
			}
			indexOfPage << "</table>";
		}
		indexOfPage << "</body></html>";
		auto indexOf = Response::FromHtml(indexOfPage);
		indexOf.Finish();
		indexOf.SendAndClose(client, headOnly);
		return true;
	}

	static bool RangeResponse(const std::filesystem::path& path, SocketType client, const std::string& rangeHeader, const bool headOnly = false)
	{
		const auto fileSize = file_size(path);
		const auto range = rangeHeader.substr(5);
		std::string::size_type comPos = 0;
		do
		{
			auto spPos = range.find('-', comPos);
			auto start = Convert::ToUint64(range.substr(comPos + 1, spPos - comPos - 1));
			comPos = range.find(',', spPos);
			decltype(start) end;
			if (comPos == std::string::npos)
			{
				if (range.length() - spPos - 1 == 0)
				{
					end = fileSize - 1;
				}
				else
				{
					end = Convert::ToUint64(range.substr(spPos + 2));
				}
			}
			else
			{
				end = Convert::ToUint64(range.substr(spPos + 1, comPos - spPos - 1));
			}
			const auto diff = end - start + 1;
			Response resp(206);
			resp.Headers[WebUtility::HttpHeadersKey::AcceptRanges] = "bytes";
			resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(diff);
			std::ostringstream contextRange{};
			contextRange << "bytes " << start << "-" << end << "/" << fileSize;
			resp.Headers[WebUtility::HttpHeadersKey::ContentRange] = contextRange.str();
			resp.SendBody = [=](const auto client)
			{
				std::ifstream fs(path, std::ios_base::in | std::ios_base::binary);
				char buf[4096];
				decltype(end) count = 0;
				fs.seekg(start);
				while (count < diff)
				{
#undef min
					fs.read(buf, std::min(static_cast<decltype(diff)>(4096), diff - count));
					const auto counted = fs.gcount();
					send(client, buf, counted, 0);
					count += counted;
				}
			};
			resp.Finish();
			resp.Send(client, headOnly);
		} while (comPos != std::string::npos);
		CloseSocket(client);
		return true;
	}
	
	bool HttpServer::Work(const SocketType client, const sockaddr_in& address)
	{
		Request req(client, address);
		if (req.Raw.empty())
		{
			char buf[1] = { 0 };
			send(client, buf, 0, 0);
			CloseSocket(client);
			return true;
		}
		if (params.CgiHook.has_value())
		{
			if (params.CgiHook.value()(req))
			{
				return true;
			}
		}
		const auto rawPath = req.Path();
		auto realPath =
			params.RootPath /
			std::filesystem::u8path(
				rawPath.substr(
					std::distance(rawPath.begin(),
						std::find_if(
							rawPath.begin(),
							rawPath.end(),
							[](const auto& x) {return !(x == '/' || x == '\\'); }))));
		if (realPath.u8string().find(params.RootPath.u8string()) != 0)
		{
			Response::FromStatusCode(400).SendAndClose(client);
			return true;
		}
		bool headOnly;
		switch (req.Method())
		{
		case WebUtility::HttpMethod::GET:
		case WebUtility::HttpMethod::POST:
		case WebUtility::HttpMethod::HEAD:
			headOnly = req.Method() == WebUtility::HttpMethod::HEAD;
			if (exists(realPath))
			{
				if (is_directory(realPath))
				{
					if (params.AutoIndexMode)
					{
						return IndexOfResponse(realPath, req, client, headOnly);
					}
					const auto pos = std::find_if(
						params.IndexPages.begin(),
						params.IndexPages.end(),
						[&](const auto& index) { return exists(realPath / index); });
					if (pos == params.IndexPages.end())
					{
						params.ForbiddenResponse.SendAndClose(client, headOnly);
						return true;
					}
					realPath /= *pos;
				}
				if (is_regular_file(realPath))
				{
					const auto rawRange = req.Header(WebUtility::HttpHeadersKey::Range);
					if (rawRange.has_value())
					{
						return RangeResponse(realPath, client, rawRange.value(), headOnly);
					}
					auto resp = Response::FromFile(realPath);
					auto ext = realPath.extension().u8string();
					std::transform(ext.begin(), ext.end(), ext.begin(), static_cast<int(*)(int)>(std::tolower));
					auto pos = WebUtility::HttpContentType.find(ext);
					if (pos != WebUtility::HttpContentType.end())
					{
						resp.Headers[WebUtility::HttpHeadersKey::ContentType] = pos->second;
					}
					resp.Finish();
					resp.SendAndClose(req.Client, headOnly);
					return true;
				}
				params.ForbiddenResponse.SendAndClose(client, headOnly);
				return true;
			}
			params.NotFoundResponse.SendAndClose(client, headOnly);
			return true;
		case WebUtility::HttpMethod::PUT:
		case WebUtility::HttpMethod::DELETE:
		case WebUtility::HttpMethod::CONNECT:
		case WebUtility::HttpMethod::OPTIONS:
		case WebUtility::HttpMethod::TRACE:
		case WebUtility::HttpMethod::PATCH:
			Response::FromStatusCode(501).SendAndClose(client);
			return true;
		}
		return false;
	}
}
