#pragma once

#include <functional>
#include <map>
#include <optional>
#include <thread>
#include <filesystem>
#include <array>
#include <future>

#include "Arguments.h"
#include "Thread.h"
#include "Macro.h"

#ifdef MacroWindows

#include <WinSock2.h>

#else

#include <sys/socket.h>
#include <netinet/in.h>

#endif


#ifdef MacroWindows

#define CloseSocket closesocket

#else

#define CloseSocket close

#endif

namespace KappaJuko
{
	constexpr std::string_view ServerVersion = "KappaJuko/0.8.1";
	constexpr std::string_view HttpVersion = "HTTP/1.1";

	using SocketType =
#ifdef MacroWindows
		SOCKET;
#else
		int;
#endif

	ArgumentOptionHpp(LogLevel, None, Error, Info, Debug)
	ArgumentOptionHpp(NetworkIoModel, Blocking, Multiplexing)

	class Logger
	{
	public:
		LogLevel Level = LogLevel::Info;
		std::filesystem::path File = {};
		bool Console = true;

		using MsgType = std::tuple<
			LogLevel,
			decltype(std::chrono::system_clock::now()),
			decltype(std::this_thread::get_id()), std::string>;
		std::thread LogThread{};
		Thread::Channel<MsgType> Chan{};
		
		template<LogLevel Level = LogLevel::Info, class...Args>
		void Write(Args&&... args)
		{
			WriteImpl<Level>(std::this_thread::get_id(), std::forward<Args>(args)...);
		}

		template<LogLevel Level = LogLevel::Info, class...Args>
		std::future<void> WriteAsync(Args&&... args)
		{
			return std::async(WriteImpl<Level>, std::launch::async, std::this_thread::get_id(), std::forward<Args>(args)...);
		}
		
	private:
		template<LogLevel Level, class...Args>
		void WriteImpl(decltype(std::this_thread::get_id()) id, Args&&... args)
		{
			std::string msg{};
			(msg.append(args), ...);
			Chan.Write(MsgType(Level, std::chrono::system_clock::now(), id, msg));
		}
	};
	
	static Logger Log{};
	
	namespace WebUtility
	{		
#if (defined MacroWindows && DELETE)
#define WinDeleteDefined
#endif
		
#ifdef WinDeleteDefined
#undef DELETE
#endif
		
		ArgumentOptionHpp(HttpMethod, GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH)
		
#ifdef WinDeleteDefined
#define DELETE (0x00010000L)
#endif

#undef WinDeleteDefined
		
		ArgumentOptionHpp(HttpHeadersKey, Accept, AcceptCH, AcceptCHLifetime, AcceptCharset, AcceptEncoding, AcceptLanguage,
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
		
		static std::unordered_map<HttpHeadersKey, std::string_view> HttpHeaders
		{
			{HttpHeadersKey::Accept, "Accept"},
			{HttpHeadersKey::AcceptCH, "Accept-CH"},
			{HttpHeadersKey::AcceptCHLifetime, "Accept-CH-Lifetime"},
			{HttpHeadersKey::AcceptCharset, "Accept-Charset"},
			{HttpHeadersKey::AcceptEncoding, "Accept-Encoding"},
			{HttpHeadersKey::AcceptLanguage, "Accept-Language"},
			{HttpHeadersKey::AcceptPatch, "Accept-Patch"},
			{HttpHeadersKey::AcceptRanges, "Accept-Ranges"},
			{HttpHeadersKey::AccessControlAllowCredentials, "Access-Control-Allow-Credentials"},
			{HttpHeadersKey::AccessControlAllowHeaders, "Access-Control-Allow-Headers"},
			{HttpHeadersKey::AccessControlAllowMethods, "Access-Control-Allow-Methods"},
			{HttpHeadersKey::AccessControlAllowOrigin, "Access-Control-Allow-Origin"},
			{HttpHeadersKey::AccessControlExposeHeaders, "Access-Control-Expose-Headers"},
			{HttpHeadersKey::AccessControlMaxAge, "Access-Control-Max-Age"},
			{HttpHeadersKey::AccessControlRequestHeaders, "Access-Control-Request-Headers"},
			{HttpHeadersKey::AccessControlRequestMethod, "Access-Control-Request-Method"},
			{HttpHeadersKey::Age, "Age"},
			{HttpHeadersKey::Allow, "Allow"},
			{HttpHeadersKey::AltSvc, "Alt-Svc"},
			{HttpHeadersKey::Authorization, "Authorization"},
			{HttpHeadersKey::CacheControl, "Cache-Control"},
			{HttpHeadersKey::ClearSiteData, "Clear-Site-Data"},
			{HttpHeadersKey::Connection, "Connection"},
			{HttpHeadersKey::ContentDisposition, "Content-Disposition"},
			{HttpHeadersKey::ContentEncoding, "Content-Encoding"},
			{HttpHeadersKey::ContentLanguage, "Content-Language"},
			{HttpHeadersKey::ContentLength, "Content-Length"},
			{HttpHeadersKey::ContentLocation, "Content-Location"},
			{HttpHeadersKey::ContentRange, "Content-Range"},
			{HttpHeadersKey::ContentSecurityPolicy, "Content-Security-Policy"},
			{HttpHeadersKey::ContentSecurityPolicyReportOnly, "Content-Security-Policy-Report-Only"},
			{HttpHeadersKey::ContentType, "Content-Type"},
			{HttpHeadersKey::Cookie, "Cookie"},
			{HttpHeadersKey::CrossOriginEmbedderPolicy, "Cross-Origin-Embedder-Policy"},
			{HttpHeadersKey::CrossOriginOpenerPolicy, "Cross-Origin-Opener-Policy"},
			{HttpHeadersKey::CrossOriginResourcePolicy, "Cross-Origin-Resource-Policy"},
			{HttpHeadersKey::DNT, "DNT"},
			{HttpHeadersKey::DPR, "DPR"},
			{HttpHeadersKey::Date, "Date"},
			{HttpHeadersKey::DeviceMemory, "Device-Memory"},
			{HttpHeadersKey::Digest, "Digest"},
			{HttpHeadersKey::ETag, "ETag"},
			{HttpHeadersKey::EarlyData, "Early-Data"},
			{HttpHeadersKey::Expect, "Expect"},
			{HttpHeadersKey::ExpectCT, "Expect-CT"},
			{HttpHeadersKey::Expires, "Expires"},
			{HttpHeadersKey::Forwarded, "Forwarded"},
			{HttpHeadersKey::From, "From"},
			{HttpHeadersKey::Host, "Host"},
			{HttpHeadersKey::IfMatch, "If-Match"},
			{HttpHeadersKey::IfModifiedSince, "If-Modified-Since"},
			{HttpHeadersKey::IfNoneMatch, "If-None-Match"},
			{HttpHeadersKey::IfRange, "If-Range"},
			{HttpHeadersKey::IfUnmodifiedSince, "If-Unmodified-Since"},
			{HttpHeadersKey::Index, "Index"},
			{HttpHeadersKey::KeepAlive, "Keep-Alive"},
			{HttpHeadersKey::LastModified, "Last-Modified"},
			{HttpHeadersKey::Link, "Link"},
			{HttpHeadersKey::Location, "Location"},
			{HttpHeadersKey::NEL, "NEL"},
			{HttpHeadersKey::Origin, "Origin"},
			{HttpHeadersKey::ProxyAuthenticate, "Proxy-Authenticate"},
			{HttpHeadersKey::ProxyAuthorization, "Proxy-Authorization"},
			{HttpHeadersKey::Range, "Range"},
			{HttpHeadersKey::Referer, "Referer"},
			{HttpHeadersKey::ReferrerPolicy, "Referrer-Policy"},
			{HttpHeadersKey::RetryAfter, "Retry-After"},
			{HttpHeadersKey::SaveData, "Save-Data"},
			{HttpHeadersKey::SecFetchDest, "Sec-Fetch-Dest"},
			{HttpHeadersKey::SecFetchMode, "Sec-Fetch-Mode"},
			{HttpHeadersKey::SecFetchSite, "Sec-Fetch-Site"},
			{HttpHeadersKey::SecFetchUser, "Sec-Fetch-User"},
			{HttpHeadersKey::SecWebSocketAccept, "Sec-WebSocket-Accept"},
			{HttpHeadersKey::Server, "Server"},
			{HttpHeadersKey::ServerTiming, "Server-Timing"},
			{HttpHeadersKey::SetCookie, "Set-Cookie"},
			{HttpHeadersKey::SourceMap, "SourceMap"},
			{HttpHeadersKey::HTTPStrictTransportSecurity, "HTTP Strict Transport Security"},
			{HttpHeadersKey::TE, "TE"},
			{HttpHeadersKey::TimingAllowOrigin, "Timing-Allow-Origin"},
			{HttpHeadersKey::Tk, "Tk"},
			{HttpHeadersKey::Trailer, "Trailer"},
			{HttpHeadersKey::TransferEncoding, "Transfer-Encoding"},
			{HttpHeadersKey::UpgradeInsecureRequests, "Upgrade-Insecure-Requests"},
			{HttpHeadersKey::UserAgent, "User-Agent"},
			{HttpHeadersKey::Vary, "Vary"},
			{HttpHeadersKey::Via, "Via"},
			{HttpHeadersKey::WWWAuthenticate, "WWW-Authenticate"},
			{HttpHeadersKey::WantDigest, "Want-Digest"},
			{HttpHeadersKey::Warning, "Warning"},
			{HttpHeadersKey::XContentTypeOptions, "X-Content-Type-Options"},
			{HttpHeadersKey::XDNSPrefetchControl, "X-DNS-Prefetch-Control"},
			{HttpHeadersKey::XFrameOptions, "X-Frame-Options"},
			{HttpHeadersKey::XXSSProtection, "X-XSS-Protection"},
		};

		static std::unordered_map<uint16_t, std::string_view> HttpStatusCodes
		{
			{100, "Continue"},
			{101, "Switching Protocol"},
			{103, "Early Hints"},
			{200, "OK"},
			{201, "Created"},
			{202, "Accepted"},
			{203, "Non - Authoritative Information"},
			{204, "No Content"},
			{205, "Reset Content"},
			{206, "Partial Content"},
			{300, "Multiple Choices"},
			{301, "Moved Permanently"},
			{302, "Found"},
			{303, "See Other"},
			{304, "Not Modified"},
			{307, "Temporary Redirect"},
			{308, "Permanent Redirect"},
			{400, "Bad Request"},
			{401, "Unauthorized"},
			{402, "Payment Required"},
			{403, "Forbidden"},
			{404, "Not Found"},
			{405, "Method Not Allowed"},
			{406, "Not Acceptable"},
			{407, "Proxy Authentication Required"},
			{408, "Request Timeout"},
			{409, "Conflict"},
			{410, "Gone"},
			{411, "Length Required"},
			{412, "Precondition Failed"},
			{413, "Payload Too Large"},
			{414, "URI Too Long"},
			{415, "Unsupported Media Type"},
			{416, "Range Not Satisfiable"},
			{417, "Expectation Failed"},
			{418, "I'm a teapot"},
			{422, "Unprocessable Entity"},
			{425, "Too Early"},
			{426, "Upgrade Required"},
			{428, "Precondition Required"},
			{429, "Too Many Requests"},
			{431, "Request Header Fields Too Large"},
			{451, "Unavailable For Legal Reasons"},
			{500, "Internal Server Error"},
			{501, "Not Implemented"},
			{502, "Bad Gateway"},
			{503, "Service Unavailable"},
			{504, "Gateway Timeout"},
			{505, "HTTP Version Not Supported"},
			{506, "Variant Also Negotiates"},
			{507, "Insufficient Storage"},
			{508, "Loop Detected"},
			{510, "Not Extended"},
			{511, "Network Authentication Required"},
		};

		static std::unordered_map<std::string_view, std::string_view> HttpContentType
		{
			{".mp4", "video/mp4"},
			{".wmv", "video/x-ms-wmv"}
		};

		static auto UrlEncodeTable = []()
		{
			std::array<bool, 256> tab{};
			for (auto i = 0; i < 256; ++i)
			{
				tab[i] = !(isalnum(i) || i == '*' || i == '-' || i == '.' || i == '_');
			}
			return tab;
		}();
		
		static std::string UrlDecode(const std::string& raw);

		static std::string UrlEncode(const std::string& raw);

		static decltype(std::chrono::system_clock::to_time_t({})) FileLastModified(const std::filesystem::path& path);

		static std::string ToGmtString(const decltype(FileLastModified({}))& time);

		static std::string ETag(const decltype(FileLastModified({}))& time, const decltype(std::filesystem::file_size({}))& size);
	}

	class Request
	{
	public:
		SocketType Client;
		std::string Raw{};
		
		explicit Request(SocketType sock, const sockaddr_in& addr);

		std::string Ip();
		std::uint16_t Port();

		WebUtility::HttpMethod Method();
		std::string Path();
		std::optional<std::string> Header(const WebUtility::HttpHeadersKey& param);
		std::optional<std::string> Get(const std::string& param);
		std::optional<std::string> Cookie(const std::string& param);
		std::optional<std::string> Post(const std::string& param);
	private:
		sockaddr_in addr;

		std::string rawMethod{};
		std::string rawUrl{};

		std::string::size_type queryPos = std::string::npos;

		std::optional<std::string> ip = std::nullopt;
		std::optional<uint16_t> port = std::nullopt;
		std::optional<std::string> path = std::nullopt;
		std::optional<std::map<WebUtility::HttpHeadersKey, std::string>> headerData = std::nullopt;
		std::optional<std::map<std::string, std::string>> getData = std::nullopt;
		std::optional<std::map<std::string, std::string>> cookieData = std::nullopt;
		std::optional<std::map<std::string, std::string>> postData = std::nullopt;
		std::optional<WebUtility::HttpMethod> method;
	};

	class Response
	{
	public:
		std::any SendBodyArgs{};
		std::optional<bool(*)(SocketType, const std::any&)> SendBody = std::nullopt;
		std::map<WebUtility::HttpHeadersKey, std::string> Headers
		{
			{WebUtility::HttpHeadersKey::Server, std::string(ServerVersion)},
		};

		explicit Response(bool keepAlive, uint16_t statusCode = 200);
		~Response() = default;
		Response(const Response& resp);
		Response(Response&& resp) noexcept;
		Response& operator=(const Response& resp);
		Response& operator=(Response&& resp) noexcept;

		void Finish();

		bool SendHead(SocketType client) const;

		bool Send(SocketType client, bool headOnly = false);

		[[nodiscard]] static Response FromStatusCodeHtml(bool keepAlive, uint16_t statusCode);

		[[nodiscard]] static Response FromHtml(bool keepAlive, const std::string& html, uint16_t statusCode = 200);

		[[nodiscard]] static Response FromFile(bool keepAlive, const std::filesystem::path& path, uint16_t statusCode = 200);

	private:
		std::ostringstream head{};
		std::string headBuf;
	};
	
	struct LauncherParams
	{
		std::filesystem::path RootPath;
		uint16_t Port = 80;
		uint16_t ThreadCount = 1;
		NetworkIoModel IoModel = NetworkIoModel::Multiplexing;
		bool AutoIndexMode = false;
		bool ImageBoard = false;
		bool NotFoundRedirect = false;
		Response NotFoundResponse = Response::FromStatusCodeHtml(true, 404);
		Response ForbiddenResponse = Response::FromStatusCodeHtml(true, 403);
		std::vector<std::string_view> IndexPages = { "index.html" };
		std::filesystem::path LogPath = "";
		LogLevel LogFileLevel = LogLevel::Info;
		bool ConsoleLog = true;
		
		std::optional<std::optional<bool>(*)(Request&)> CgiHook = std::nullopt;

		[[nodiscard]] static LauncherParams FromArgs(int args, char** argv);
	};

	class KappaJukoException : public std::runtime_error { using std::runtime_error::runtime_error; };
	
	class InitializationException : public KappaJukoException { using KappaJukoException::KappaJukoException; };
	class CreateSocketException final : public InitializationException { using InitializationException::InitializationException; };
	class BindPortException final : public InitializationException { using InitializationException::InitializationException; };

	class RunException : public KappaJukoException { using KappaJukoException::KappaJukoException; };
	class ResponseException final : public RunException { using RunException::RunException; };
	class RequestException : public RunException { using RunException::RunException; };
	class RequestParseError final : public RequestException { using RequestException::RequestException; };
	
	class HttpServer
	{
	public:
		explicit HttpServer(LauncherParams params, const std::function<void()>& logThread = DefaultLogThread);
		~HttpServer() = default;

		HttpServer() = delete;
		HttpServer(const HttpServer& httpServer) = delete;
		HttpServer(HttpServer&& httpServer) = delete;
		HttpServer operator=(const HttpServer& httpServer) = delete;
		HttpServer operator=(HttpServer&& httpServer) = delete;
		
		void Init();
		void Run();
		void Close() const;

		static bool IndexOf(const std::filesystem::path& path, Request& request, Response& forbiddenResponse, bool keepAlive, bool imageBoard = false, bool headOnly = false);
		
	private:
		LauncherParams params;
		SocketType serverSocket = -1;
		std::vector<std::thread> threadPool = std::vector<std::thread>();

		bool Work(SocketType client, const sockaddr_in& address, bool keepAlive);

		static void DefaultLogThread();
	};
}
