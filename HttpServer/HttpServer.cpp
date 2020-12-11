#include <filesystem>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <queue>
#include <list>
#include <unordered_set>
#include <iomanip>
#include <utility>

#include "HttpServer.h"
#include "Convert.h"
#include "Function.h"
#include "Exception.h"
#include "Macro.h"
#include "String.h"
#include "Time.h"

#ifdef MacroWindows

#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "User32.lib")

#else

#include <arpa/inet.h>
#include <dirent.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <csignal>
#include <netdb.h>

#endif

#define KappaJukoThrow(ex, ...) ExceptionThrow(ex, __VA_ARGS__, "\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")")

namespace KappaJuko
{
	ArgumentOptionCpp(LogLevel, None, Error, Info)
	
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
						[&](const uint8_t x) { return UrlEncodeTable[x]; });
				if (pos == raw.end())
				{
					res.append(raw, i);
					break;
				}
				const auto dis = std::distance(beg, pos);
				res.append(raw, i, dis);
				res.append("%");
				res.append(Convert::ToString<uint8_t>(*pos, 16));
				i += dis;
			}
			return res;
		}

		decltype(std::chrono::system_clock::to_time_t({})) FileLastModified(const std::filesystem::path& path)
		{
			return std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(
					last_write_time(path)
					- decltype(std::filesystem::last_write_time({}))::clock::now()
					+ std::chrono::system_clock::now()));
		}

		std::string ToGmtString(const decltype(FileLastModified({}))& time)
		{
			tm gmt{};
			Time::Gmt(&gmt, &time);
			std::ostringstream ss{};
			ss << std::put_time(&gmt, "%a, %d %b %G %T GMT");
			return ss.str();
		}
		
		std::string ETag(const decltype(FileLastModified({}))& time, const decltype(std::filesystem::file_size({}))& size)
		{
			std::string res{};
			res.append(Convert::ToString(std::chrono::seconds(time).count(), 16));
			res.append("-");
			res.append(Convert::ToString(size, 16));
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
	}

	std::string Request::Ip()
	{
		if (!ip.has_value())
		{
			char host[NI_MAXHOST] = { 0 };
			getnameinfo((sockaddr*)&addr, sizeof(addr),
				host, NI_MAXHOST,
				NULL, 0,
				NI_NUMERICHOST);
			ip = host;
		}
		return ip.value();
	}

	std::uint16_t Request::Port()
	{
		if (!port.has_value())
		{
			port = ntohs(addr.sin_port);
		}
		return port.value();
	}

	WebUtility::HttpMethod Request::Method()
	{
		if (!method.has_value())
		{
			rawMethod = Raw.substr(0, Raw.find(' '));
			String::ToUpper(rawMethod);
			method = WebUtility::ToHttpMethod(rawMethod);
			if (!method.has_value())
			{
				rawMethod.erase(std::remove(rawMethod.begin(), rawMethod.end(), '\r'), rawMethod.end());
				rawMethod.erase(std::remove(rawMethod.begin(), rawMethod.end(), '\n'), rawMethod.end());
				KappaJukoThrow(RequestParseError, "Unrecognized Method: ", rawMethod);
			}
		}
		return method.value();
	}
	
	std::string Request::Path()
	{
		if (!path.has_value())
		{
			Method();
			try
			{
				const auto offset = rawMethod.length() + 1;
				rawUrl = Raw.substr(offset, Raw.find(' ', offset) - offset);
				queryPos = rawUrl.find('?');
				path = WebUtility::UrlDecode(rawUrl.substr(0, queryPos));
			}
			catch (const std::exception& ex)
			{
				Raw.erase(std::remove(Raw.begin(), Raw.end(), '\r'), Raw.end());
				Raw.erase(std::remove(Raw.begin(), Raw.end(), '\n'), Raw.end());
				KappaJukoThrow(RequestParseError, ex.what(), ": Unrecognized Path: ", rawMethod);
			}
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
		Headers[WebUtility::HttpHeadersKey::Date] = WebUtility::ToGmtString(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
		for (const auto& [key, value] : Headers)
		{
			head << WebUtility::HttpHeaders[key] << ": " << value << "\r\n";
		}
		head << "\r\n";
		headBuf = head.str();
	}
	
	bool Response::SendHead(const SocketType client) const
	{
		if (send(client, headBuf.c_str(), headBuf.length(), 0) <= 0) return false;
		Log.Write("\n", headBuf);
		return true;
	}

	bool Response::Send(const SocketType client, const bool headOnly)
	{
		if (SendHead(client))
		{
			if (!headOnly)
			{
				if (SendBody.has_value())
				{
					SendBody.value()(client);
				}
			}
			return true;
		}
		return false;
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
			if (send(client, buf.c_str(), buf.length(), 0) <= 0)return;
		};
		return resp;
	}
	
	Response Response::FromFile(const std::filesystem::path& path, const uint16_t statusCode)
	{
		Response resp(statusCode);
		const auto fileSize = file_size(path);
		const auto fileLastModified = WebUtility::FileLastModified(path);
		resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(fileSize);
		resp.Headers[WebUtility::HttpHeadersKey::LastModified] = WebUtility::ToGmtString(fileLastModified);
		resp.Headers[WebUtility::HttpHeadersKey::ETag] = WebUtility::ETag(fileLastModified, fileSize);
		resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";

		resp.SendBody = [&](const auto client)
		{
			std::ifstream fs(path, std::ios_base::in | std::ios_base::binary);
			char buf[4096];
			do
			{
				fs.read(buf, 4096);
				if (send(client, buf, fs.gcount(), 0) <= 0)return;
			}
			while (!fs.eof());
		};
		return resp;
	}
	
	LauncherParams LauncherParams::FromArgs(const int _args, char** _argv)
	{
		const auto toString = [](const auto& x) { return std::string(x); };
		const auto toInt = std::bind(Convert::ToInt, std::placeholders::_1, 10);
		const auto stringToInt = Function::Compose(toString, toInt);
		
		using ArgumentsParse::Arguments;
		using ArgumentsParse::Argument;
		Arguments args{};
#define ArgumentsFunc(arg) [&](decltype(arg)::ConvertFuncParamType value) -> decltype(arg)::ConvertResult
#define ArgumentsValue(arg) args.Value<decltype(arg)::ValueType>(arg)
		Argument<std::filesystem::path> configFile
		{
			"-c",
			"config file"
		};
		Argument<std::filesystem::path> rootPath
		{
			"-r",
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
		Argument<decltype(Port)> port
		{
			"-p",
			"port(80)",
			80,
			ArgumentsFunc(port)
			{
				return {static_cast<uint16_t>(stringToInt(value)), {}};
			}
		};
		Argument<decltype(ThreadCount)> threadCount
		{
			"-t",
			"work thread count(1)",
			1,
			ArgumentsFunc(threadCount)
			{
				return {
					static_cast<uint16_t>(stringToInt(value)),
					{}
				};
			}
		};
		Argument<decltype(IoModel)> ioModel
		{
			"--iomodel",
			"network IO model " + WebUtility::NetworkIoModelDesc(ToString(WebUtility::NetworkIoModel::Multiplexing)),
			WebUtility::NetworkIoModel::Multiplexing,
			ArgumentsFunc(ioModel)
			{
				return {Function::Compose(toString, WebUtility::ToNetworkIoModel)(value), {}};
			}
		};
		Argument<decltype(AutoIndexMode), 0> autoIndexMode
		{
			"--autoindex",
			"auto index mode",
			false,
			ArgumentsFunc(autoIndexMode)
			{
				return {true, {}};
			}
		};
		Argument<decltype(ImageBoard), 0> imageBoard
		{
			"--imageboard",
			"auto index mode with image board",
			false,
			ArgumentsFunc(autoIndexMode)
			{
				return {true, {}};
			}
		};
		Argument<decltype(NotFoundRedirect), 0> notFoundRedirect
		{
			"--redirect",
			"not found redirect",
			false,
			ArgumentsFunc(notFoundRedirect)
			{
				return {true, {}};
			}
		};
		Argument<decltype(NotFoundResponse)> notFoundResponse
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
		Argument<decltype(ForbiddenResponse)> forbiddenResponse
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
		Argument<decltype(IndexPages)> indexPages
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
		Argument<decltype(LogPath)> logPath
		{
			"-l",
			"log file",
			""
		};
		Argument<decltype(LogFileLevel)> logLevel
		{
			"--loglevel",
			"log level",
			LogLevel::Info,
			ArgumentsFunc(logLevel)
			{
				return {Function::Compose(toString, ToLogLevel)(value), {}};
			}
		};
		Argument<decltype(ConsoleLog), 0> consoleLog
		{
			"--disableconsolelog",
			"disable console log",
			true,
			ArgumentsFunc(consoleLog)
			{
				return {false, {}};
			}
		};
		args.Add(rootPath);
		args.Add(port);
		args.Add(threadCount);
		args.Add(ioModel);
		args.Add(autoIndexMode);
		args.Add(imageBoard);
		args.Add(notFoundRedirect);
		args.Add(notFoundResponse);
		args.Add(forbiddenResponse);
		args.Add(indexPages);
		args.Add(logPath);
		args.Add(logLevel);
		args.Add(consoleLog);
		try
		{
			args.Parse(_args, _argv);

			const auto imageBoardVal = ArgumentsValue(imageBoard);
			const auto autoIndexModeVal = imageBoardVal ? true : ArgumentsValue(autoIndexMode);
			
			return
			{
				ArgumentsValue(rootPath),
				ArgumentsValue(port),
				ArgumentsValue(threadCount),
				ArgumentsValue(ioModel),
				autoIndexModeVal,
				imageBoardVal,
				ArgumentsValue(notFoundRedirect),
				ArgumentsValue(notFoundResponse),
				ArgumentsValue(forbiddenResponse),
				ArgumentsValue(indexPages),
				ArgumentsValue(logPath),
				ArgumentsValue(logLevel),
				ArgumentsValue(consoleLog)
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

	HttpServer::HttpServer(LauncherParams params, const std::function<void()>& logThread): params(std::move(params))
	{
		Log.Level = this->params.LogFileLevel;
		Log.File = this->params.LogPath;
		Log.Console = this->params.ConsoleLog;
		Log.LogThread = std::thread(logThread);
	}

	void HttpServer::Init()
	{
#ifdef MacroWindows
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
#ifdef MacroWindows
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
			KappaJukoThrow(BindPortException, "Can't bind port ", params.Port);
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
						auto addrLen = sizeof clientAddr;
						const auto client = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), reinterpret_cast<socklen_t*>(&addrLen));
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
							Log.Write<LogLevel::Error>(
								"\nException in thread \"", Convert::ToString(id), "\" java.lang.NullPointerException: ", ex.what(),
								"\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")\n");
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

	static bool IndexOfBody(const std::filesystem::path& path, std::ostringstream& page, bool imageBoard = false)
	{
		std::unordered_set<std::string_view> imageTypes{".png", ".jpg", ".jpeg", ".webp", ".gif"};
		using UrlType = std::string;
		using Utf8UrlType = std::tuple<std::string, std::string>;
		using Utf8UrlSizeType = std::tuple<std::string, std::string, uint64_t>;
		std::priority_queue<Utf8UrlType, std::vector<Utf8UrlType>, std::greater<>> dirs{};
		std::priority_queue<Utf8UrlSizeType, std::vector<Utf8UrlSizeType>, std::greater<>> files{};
		std::priority_queue<UrlType, std::vector<UrlType>, std::greater<>> images{};
		std::error_code errorCode;
		const std::error_code nonErrorCode;
		const std::filesystem::directory_iterator end;
		for (std::filesystem::directory_iterator file(path, std::filesystem::directory_options::none, errorCode); file != end; ++file)
		{
			if (errorCode != nonErrorCode)
			{
				return false;
			}
			const auto fnu8 = file->path().filename().u8string();
			const auto fn = WebUtility::UrlEncode(fnu8);
			if (file->is_regular_file())
			{
				if (imageBoard)
				{
					auto ext = file->path().extension().u8string();
					String::ToLower(ext);
					if (imageTypes.find(ext) != imageTypes.end())
					{
						images.emplace(fn);
						continue;
					}
				}
				files.emplace(fnu8, fn, file->file_size());
			}
			else if (file->is_directory())
			{
				dirs.emplace(fnu8, fn);
			}
		}

		page << "<a href=\"../\">../</a><br/>";
		while (!dirs.empty())
		{
			const auto& [fnu8, fn] = dirs.top();
			page << "<a href=\"" << fn << "/\">" << fnu8 << "/</a><br/>";
			dirs.pop();
		}
		if (!files.empty())
		{
			page <<
				"<hr>"
				"<table>"
				"<tr><th>File Name</th><th>Size</th></tr>";
			while (!files.empty())
			{
				const auto& [fnu8, fn, sz] = files.top();
				page << "<tr><td><a href=\"" << fn << "\">" << fnu8 << "</a></td><td>" << sz << "</td></tr>";
				files.pop();
			}
			page << "</table>";
		}
		if (!images.empty())
		{
			page <<
				"<hr>"
				"<ul>";
			while (!images.empty())
			{
				page << "<li><img src=\"" << images.top() << "\"/></li>";
				images.pop();
			}
			page << "</ul>";
		}
		return true;
	}
	
	bool HttpServer::IndexOf(const std::filesystem::path& path, Request& request, SocketType client,
		bool imageBoard, bool headOnly)
	{
		const auto indexOfPath = request.Path();
		std::ostringstream indexOfPage{};
		indexOfPage <<
			"<!DOCTYPE html>"
			"<html>"
			"<head><title>Index of " << indexOfPath << "</title>"
			"<meta charset=\"utf-8\"/>"
			"<style type=\"text/css\">"
				"body {"
					"background: #222;"
					"color: #ddd;"
					"font-family: " u8R"("Lato", "Hiragino Sans GB", "Source Han Sans SC", "Source Han Sans CN", "Noto Sans CJK SC", "WenQuanYi Zen Hei", "WenQuanYi Micro Hei", "微软雅黑", sans-serif;)"
				"}"
				"a {"
					"text-decoration: none;"
				"}"
				"a:link, a:visited {"
					"color: #6793cf;"
				"}"
				"a:hover, a:active, a:focus {"
					"color: #62bbe7;"
				"}"
				"tr td:nth-child(2) {"
					"text-align: right;"
				"{"
			"</style>";

		if (imageBoard)
		{
			indexOfPage <<
				"<style type=\"text/css\">"
					"li {"
						"width: 260px;"
						"height: 260px;"
						"float: left;"
						"margin-left: 10px;"
						"margin-top: 10px;"
						"list-style-type: none;"
					"}"
					"img {"
						"max-width: 100%;"
						"max-height: 100%;"
						"position: relative;"
						"left: 50%;"
						"top: 50%;"
						"transform: translate(-50%, -50%);"
					"}"
					"#preview {"
						"background-color: rgba(0, 0, 0, 0.8);"
						"width: 100%;"
						"height: 100%;"
						"position: fixed;"
						"top: 0;"
						"left: 0;"
						"z-index: 100;"
					"}"
					"#preview img {"
						"left: 50%;"
						"top: 50%;"
						"transform: translate(-50%, -50%);"
						"position: relative;"
					"}"
				"</style>"
				"<script type=\"application/javascript\">"
					"document.onreadystatechange = () =>"
						"[...document.getElementsByTagName('img')].forEach(x => {"
							"x.onclick = () => {"
								"let pv = document.createElement('div');"
								"pv.id = 'preview';"
								"pv.onclick = () => document.getElementById('preview').remove();"
								"let pic = document.createElement('img');"
								"pic.src = x.src;"
								"pv.appendChild(pic);"
								"[...document.getElementsByTagName('body')].forEach(x => x.appendChild(pv));"
							"};"
						"});"
				"</script>";
		}
		indexOfPage <<
			"</head>"
			"<body>"
			"<h1>Index of " << indexOfPath << "</h1><hr>";

		if (!IndexOfBody(path, indexOfPage, imageBoard))
		{
			params.ForbiddenResponse.SendAndClose(client);
			return true;
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
					if (send(client, buf, counted, 0) < 0) return;
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
		try
		{
			if (Log.Level >= LogLevel::Info)
			{
				Log.Write(" [", req.Ip(), ":", Convert::ToString(req.Port()), "]\n", req.Raw);
			}
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
			if (params.LogFileLevel >= LogLevel::Debug)
			{
				Log.Write<LogLevel::Debug>(" [", req.Ip(), ":", Convert::ToString(req.Port()), "]\n", rawPath);
			}
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
			auto headOnly = false;
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
							return IndexOf(realPath, req, client, params.ImageBoard, headOnly);
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
						const auto ifNoneMatch = req.Header(WebUtility::HttpHeadersKey::IfNoneMatch);
						const auto ifModified = req.Header(WebUtility::HttpHeadersKey::IfModifiedSince);
						if (ifNoneMatch.has_value())
						{
							if (WebUtility::ETag(WebUtility::FileLastModified(realPath), file_size(realPath)) == ifNoneMatch)
							{
								Response resp(304);
								resp.Headers[WebUtility::HttpHeadersKey::ETag] = ifNoneMatch.value();
								resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";
								if (ifModified.has_value())
								{
									resp.Headers[WebUtility::HttpHeadersKey::LastModified] = ifModified.value();
								}
								resp.Finish();
								resp.SendHead(client);
								CloseSocket(client);
								return true;
							}
						}
						else if (ifModified.has_value())
						{
							const auto lm = WebUtility::ToGmtString(WebUtility::FileLastModified(realPath));
							if (lm == ifModified.value())
							{
								Response resp(304);
								resp.Headers[WebUtility::HttpHeadersKey::LastModified] = ifModified.value();
								resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";
								resp.Finish();
								resp.SendHead(client);
								CloseSocket(client);
								return true;
							}
						}
						const auto rawRange = req.Header(WebUtility::HttpHeadersKey::Range);
						if (rawRange.has_value())
						{
							return RangeResponse(realPath, client, rawRange.value(), headOnly);
						}
						auto resp = Response::FromFile(realPath);
						auto ext = realPath.extension().u8string();
						String::ToLower(ext);
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
		catch (const KappaJukoException&)
		{
			CloseSocket(client);
			throw;
		}
		catch (const std::exception& ex)
		{
			Log.Write<LogLevel::Error>(
				"[", req.Ip(), ":", Convert::ToString(req.Port()), "] [Unknown Error] [", ex.what(), "]\n", req.Raw);
			throw;
		}
	}
	
	void HttpServer::DefaultLogThread()
	{
		std::ofstream fs{};
		while (true)
		{
			const auto& [l, t, i, s] = Log.Chan.Read();
			if (l <= Log.Level)
			{
				auto time = std::chrono::system_clock::to_time_t(t);
				tm local{};
				Time::Local(&local, &time);
				std::ostringstream buf{};
				buf << std::put_time(&local, "[%F %X] [") << ToString(l) << "] [" << i << "]";
				auto log = buf.str();
				log.append(s);
				if (Log.Console)
				{
					if (l == LogLevel::Error)
					{
						fputs(log.c_str(), stderr);
					}
					else
					{
						puts(log.c_str());
					}
				}
				if (!Log.File.empty())
				{
					fs.open(Log.File, std::ios::app | std::ios::binary);
					fs << log << "\n";
					fs.close();
				}
			}
		}
	}
}
