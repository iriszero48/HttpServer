#include <filesystem>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <queue>
#include <list>
#include <unordered_set>
#include <iomanip>
#include <random>

#include "HttpServer.h"
#include "Convert.h"
#include "Function.h"
#include "Exception.h"
#include "Macro.h"
#include "String.h"
#include "Time.h"
#include "Thread.h"

#ifdef MacroWindows

#include <atomic>
#include <utility>

#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "User32.lib")

typedef struct
{
    WSAOVERLAPPED Overlapped;
    SOCKET Socket;
    WSABUF wsaBuf;
    char Buffer[1024];
    DWORD BytesSent;
    DWORD BytesToSend;
} PER_IO_DATA, * LPPER_IO_DATA;

#else

#include <arpa/inet.h>
#include <dirent.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <csignal>
#include <netdb.h>
#include <sys/epoll.h>
#include <unistd.h>
//#include <fcntl.h>

#endif

#define KappaJukoThrow(ex, ...) ExceptionThrow(ex, __VA_ARGS__, "\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")")
#define IfFalseReturnFalse(x) if (!(x)) { return false; }

namespace KappaJuko
{
    ArgumentOptionCpp(NetworkIoModel, Blocking, Multiplexing)

    namespace WebUtility
    {
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
                res.append(1, (Convert::FromString<uint8_t>(raw.substr(pos + 1, 2), 16)));
                i = pos + 3;
            }
            return res;
        }

        static auto UrlEncodeFindIfFunc(const uint8_t x)
        {
            return UrlEncodeTable[x];
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
                auto pos = std::find_if(beg, raw.end(), UrlEncodeFindIfFunc);
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

    //Request::Request(const SocketType sock, const sockaddr_in& addr) : Client(sock), addr(addr)


    Request::Request(const SocketType sock, const sockaddr_in& addr, const decltype(RecvFunc) recvFunc,
                     std::any recvFuncArgs)
	: RecvFuncArgs(std::move(recvFuncArgs)), RecvFunc(recvFunc), Client(sock), addr(addr)
{
        int len;
        char buf[4097] = { 0 };
        do
        {
            len = RecvFunc(Client, buf, 4096, RecvFuncArgs);
            buf[len] = 0;
            Raw.append(buf);
        } while (len == 4096);
    }
	
    std::string Request::Ip()
    {
        if (!ip.has_value())
        {
            char host[NI_MAXHOST] = { 0 };
            getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                host, NI_MAXHOST,
                nullptr, 0,
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
                auto found = false;
                auto key = WebUtility::HttpHeaders.begin();
                auto end = WebUtility::HttpHeaders.end();
            	for (; key != end; ++key)
            	{
	                if (key->second == keyStr)
	                {
                        found = true;
                        break;
	                }
            	}
                if (found)
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

    std::optional<std::string> Request::Cookie(const std::string& param)
    {
        if (!cookieData.has_value())
        {
            const auto rawCookieOpt = Header(WebUtility::HttpHeadersKey::Cookie);
            if (!rawCookieOpt.has_value())
            {
                return std::nullopt;
            }
            const auto rawCookie = Header(WebUtility::HttpHeadersKey::Cookie).value();
            cookieData = std::map<std::string, std::string>{};
            auto pos = std::string::npos - 1;
            while (true)
            {
                pos += 2;
                auto i = rawCookie.find('=', pos);
                auto k = rawCookie.substr(pos, i - pos);
                pos = rawCookie.find(';', i + 1);
                i++;
                if (pos == std::string::npos)
                {
                    cookieData->emplace(k, rawCookie.substr(i));
                    break;
                }
                cookieData->emplace(k, rawCookie.substr(i, pos - i));
            }
        }
        const auto pos = cookieData->find(param);
        if (pos == cookieData->end())
        {
            return std::nullopt;
        }
        return pos->second;
    }

    std::optional<std::string> Request::Post(const std::string& param)
    {
        if (!postData.has_value())
        {
            const auto rawPost = Raw.substr(Raw.find("\r\n\r\n") + 4);
            postData = std::map<std::string, std::string>{};
            auto pos = std::string::npos;
            while (true)
            {
                pos++;
                auto i = rawPost.find('=', pos);
                auto k = rawPost.substr(pos, i - pos);
                pos = rawPost.find('&', i + 1);
                i++;
                if (pos == std::string::npos)
                {
                    postData->emplace(k, rawPost.substr(i));
                    break;
                }
                postData->emplace(k, rawPost.substr(i, pos - i));
            }
        }
        const auto pos = postData->find(param);
        if (pos == postData->end())
        {
            return std::nullopt;
        }
        return pos->second;
    }
	
    int Request::DefaultRecvFunc(const SocketType client, char* buf, const std::uint16_t len, const std::any&)
    {
        return recv(client, buf, len, 0);
    }

    Response::Response(const bool keepAlive, const decltype(SendFunc) sendFunc, std::any sendFuncArgs, const uint16_t statusCode)
	    :SendFuncArgs(std::move(sendFuncArgs)), SendFunc(sendFunc)
    {
        Headers[WebUtility::HttpHeadersKey::Connection] = keepAlive ? "keep-alive" : "close";
        String::StringCombine(
            head, HttpVersion, " ", Convert::ToString(statusCode), " ", WebUtility::HttpStatusCodes.at(statusCode), "\r\n");
    }
	
    //Response::Response(const Response& resp)
    //{
    //    SendFuncArgs = resp.SendFuncArgs;
    //    SendFunc = resp.SendFunc;
    //    SendBodyArgs = resp.SendBodyArgs;
    //    SendBody = resp.SendBody;
    //    Headers = resp.Headers;
    //    head = resp.head;
    //}
    //
    //Response::Response(Response&& resp) noexcept
    //{
    //    SendFuncArgs = resp.SendFuncArgs;
    //    SendFunc = resp.SendFunc;
    //    SendBodyArgs = resp.SendBodyArgs;
    //    SendBody = resp.SendBody;
    //    Headers = resp.Headers;
    //    head = resp.head;
    //}
    //
    //Response& Response::operator=(const Response& resp)
    //{
    //    SendFuncArgs = resp.SendFuncArgs;
    //    SendFunc = resp.SendFunc;
    //    SendBodyArgs = resp.SendBodyArgs;
    //    SendBody = resp.SendBody;
    //    Headers = resp.Headers;
    //    head = resp.head;
    //    return *this;
    //}
    //
    //Response& Response::operator=(Response&& resp) noexcept
    //{
    //    SendFuncArgs = resp.SendFuncArgs;
    //    SendFunc = resp.SendFunc;
    //    SendBodyArgs = resp.SendBodyArgs;
    //    SendBody = resp.SendBody;
    //    Headers = resp.Headers;
    //    head = resp.head;
    //    return *this;
    //}

    void Response::Finish()
    {
        Headers[WebUtility::HttpHeadersKey::Date] = WebUtility::ToGmtString(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        for (const auto& [key, value] : Headers)
        {
            String::StringCombine(head, WebUtility::HttpHeaders.at(key), ": ", value, "\r\n");
        }
        String::StringCombine(head, "\r\n");
    }

    bool Response::SendHead(const SocketType client) const
    {
        IfFalseReturnFalse(SendFunc(client, head.c_str(), head.length(), SendBodyArgs))
        LogInfo("\n", head);
        return true;
    }

    bool Response::Send(const SocketType client, const bool headOnly) const
    {
        IfFalseReturnFalse(SendHead(client))
        if (!headOnly)
        {
            if (SendBody.has_value())
            {
                IfFalseReturnFalse((**SendBody)(client, SendFunc, SendFuncArgs, SendBodyArgs))
            }
        }
        return true;
    }
	
    bool Response::DefaultSendFunc(const SocketType client, const char* buf, const std::uint32_t len, const std::any&)
    {
        return !(send(client, buf, len, 0) < 0);
    }
	
    Response Response::FromStatusCodeHtml(const bool keepAlive, const decltype(SendFunc) sendFunc, const std::any& sendFuncArgs,
        const uint16_t statusCode)
    {
        std::string page;
        const auto sc = Convert::ToString(statusCode);
        String::StringCombine(
            page,
            "<html><head><title>", sc, "</title></head>",
            "<body><h1>", sc, " - ", WebUtility::HttpStatusCodes.at(statusCode), "</h1><br/><hr>",
            ServerVersion,
            "</body></html>");
        auto resp = FromHtml(keepAlive, page, sendFunc, sendFuncArgs, statusCode);
        resp.Finish();
        return resp;
    }

    static auto FromHtmlFunc(const SocketType client,const decltype(Response::SendFunc) sendFunc,
        const std::any& sendFuncArgs, const std::any& args)
    {
        const auto buf = std::any_cast<std::string>(args);
        IfFalseReturnFalse(sendFunc(client, buf.c_str(), buf.length(), sendFuncArgs))
        return true;
    };
	
    Response Response::FromHtml(const bool keepAlive, const std::string& html, const decltype(SendFunc) sendFunc,
	    const std::any& sendFuncArgs, const uint16_t statusCode)
    {
        Response resp(keepAlive, sendFunc, sendFuncArgs, statusCode);
        resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(html.length());
        resp.SendBodyArgs = html;
        resp.SendBody = FromHtmlFunc;
        return resp;
    }

    static auto FromFileFunc(const SocketType client, const decltype(Response::SendFunc) sendFunc,
        const std::any& sendFuncArgs, const std::any& args)
    {
        std::ifstream fs(std::any_cast<std::filesystem::path>(args), std::ios_base::in | std::ios_base::binary);
        char buf[4096];
        do
        {
            fs.read(buf, 4096);
            IfFalseReturnFalse(sendFunc(client, buf, fs.gcount(), sendFuncArgs))
        } while (!fs.eof());
            return true;
    };
	
    Response Response::FromFile(const bool keepAlive, const std::filesystem::path& path, const decltype(SendFunc) sendFunc,
	    const std::any& sendFuncArgs, const uint16_t statusCode)
    {
        Response resp(keepAlive, sendFunc, sendFuncArgs, statusCode);
        const auto fileSize = file_size(path);
        const auto fileLastModified = WebUtility::FileLastModified(path);
        resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(fileSize);
        resp.Headers[WebUtility::HttpHeadersKey::LastModified] = WebUtility::ToGmtString(fileLastModified);
        resp.Headers[WebUtility::HttpHeadersKey::ETag] = WebUtility::ETag(fileLastModified, fileSize);
        resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";
        resp.SendBodyArgs = path;
        resp.SendBody = FromFileFunc;
        return resp;
    }

    LauncherParams LauncherParams::FromArgs(const int _args, char** _argv)
    {
        const auto toString = [](const auto& x) { return std::string(x); };
        const auto toInt = std::bind(Convert::FromString<uint64_t, std::string>, std::placeholders::_1, 10);
        const auto stringToInt = Function::Compose(toString, toInt);

        using ArgumentsParse::Arguments;
        using ArgumentsParse::Argument;
        Arguments args{};
#define ArgumentsFunc(arg) [&](decltype(arg)::ConvertFuncParamType value) -> decltype(arg)::ConvertResult
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
                "network IO model " + NetworkIoModelDesc(ToString(NetworkIoModel::Multiplexing)),
                NetworkIoModel::Multiplexing,
                ArgumentsFunc(ioModel)
                {
                    return {Function::Compose(toString, ToNetworkIoModel)(value), {}};
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
        		std::filesystem::path{}
        };
        Argument<decltype(ForbiddenResponse)> forbiddenResponse
        {
                "--403",
                "403 page",
                std::filesystem::path{}
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

            LogInfo("Server start...\n", args.GetValuesDesc({
                args.GetValuesDescConverter<std::filesystem::path          >([](const auto& x) { return x.string(); }),
                args.GetValuesDescConverter<bool                           >([](const auto& x) { return x ? "true" : "false"; }),
                args.GetValuesDescConverter<decltype(indexPages)::ValueType>([](const auto& x) { std::string buf("["); for (const auto& xs : x) { buf.append(xs); buf.append(";"); } return buf + "]"; }),
                args.GetValuesDescConverter<KappaJuko::NetworkIoModel      >([](const auto& x) { return ToString(x); }),
                args.GetValuesDescConverter<LogLevel                       >([](const auto& x) { return ToString(x); }),
                args.GetValuesDescConverter<uint16_t                       >([](const auto& x) { return Convert::ToString(x); })
            }));
        	
            const auto imageBoardVal = args.Value(imageBoard);
            const auto autoIndexModeVal = imageBoardVal ? true : args.Value(autoIndexMode);

            return
            {
                    args.Value(rootPath),
					args.Value(notFoundResponse),
                    args.Value(forbiddenResponse),
                    args.Value(port),
                    args.Value(threadCount),
                    args.Value(ioModel),
                    autoIndexModeVal,
                    imageBoardVal,
                    args.Value(notFoundRedirect),
                    args.Value(indexPages),
                    args.Value(logPath),
                    args.Value(logLevel),
                    args.Value(consoleLog)
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

    HttpServer::HttpServer(LauncherParams params) : params(std::move(params))
    {
        LogThread = std::thread(DefaultLogThread, this->params.LogFileLevel, this->params.LogPath, this->params.ConsoleLog);
    }
	
    HttpServer::HttpServer(LauncherParams params, const std::function<void(const LauncherParams&)>& logThread) : params(std::move(params))
    {
        LogThread = std::thread(logThread, params);
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

#ifdef MacroWindows
        if (params.IoModel == NetworkIoModel::Multiplexing)
        {
            serverSocket = WSASocket(
                AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        }
        else
#endif
        {
            serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }

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

        char optVal[4] = { 0 };
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
	
#ifdef MacroWindows
    static DWORD WINAPI ServerWorkerThread(const LPVOID lpParameter)
    {
	    const auto hCompletionPort = static_cast<HANDLE>(lpParameter);
        DWORD numBytesSent = 0;
        ULONG completionKey;
        LPPER_IO_DATA perIoData;

        while (GetQueuedCompletionStatus(
            hCompletionPort, &numBytesSent,
            reinterpret_cast<PULONG_PTR>(&completionKey),
            reinterpret_cast<LPOVERLAPPED*>(&perIoData),
            INFINITE))
        {
            if (!perIoData)
                continue;
            
            if (numBytesSent == 0)
            {
                std::cout << "Client disconnected!\r\n\r\n";
            }
            else
            {
                perIoData->BytesSent += numBytesSent;
                if (perIoData->BytesSent < perIoData->BytesToSend)
                {
                    perIoData->wsaBuf.buf = &(perIoData->Buffer[perIoData->BytesSent]);
                    perIoData->wsaBuf.len = (perIoData->BytesToSend - perIoData->BytesSent);
                }
                else
                {
                    perIoData->wsaBuf.buf = perIoData->Buffer;
                    perIoData->wsaBuf.len = strlen(perIoData->Buffer);
                    perIoData->BytesSent = 0;
                    perIoData->BytesToSend = perIoData->wsaBuf.len;
                }

                if (WSASend(perIoData->Socket, &(perIoData->wsaBuf), 1, &numBytesSent, 0, &(perIoData->Overlapped), NULL) == 0)
                    continue;

                if (WSAGetLastError() == WSA_IO_PENDING)
                    continue;
            }

            closesocket(perIoData->Socket);
            delete perIoData;
        }

        return 0;
    }
#else
    static void addEvent(const int epoll, const SocketType sock, const decltype(epoll_event{}.events) status)
    {
        epoll_event ev;
        ev.events = status;
        ev.data.fd = sock;
        epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &ev);
    };
#endif
	
    void HttpServer::Run()
    {
        threadPool = std::vector<std::thread>();
        if (params.IoModel == NetworkIoModel::Blocking)
        {
            static const auto SendFunc = Response::DefaultSendFunc;
            static const std::any SendFuncArgs = {};
            static const auto RecvFunc = Request::DefaultRecvFunc;
            static const std::any RecvFuncArgs = {};
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
                        bool alive;
                        try
                        {
                            WorkParams workParams
                            {
                            	client,
                            	clientAddr,
                            	false,
                            	RecvFunc,
                            	RecvFuncArgs,
                            	SendFunc,
                            	SendFuncArgs
                            };
                             alive = Work(workParams);
                        }
                        catch (const KappaJukoException& ex)
                        {
                            alive = false;
                            LogError(
                                "\nException in thread \"", Convert::ToString(id), "\" java.lang.NullPointerException: ", ex.what(),
                                "\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")\n");
                        }
                    	if(!alive)
                    	{
                            CloseSocket(client);
                    	}
                    }
                }, i);
            }
        }
        else if (params.IoModel == NetworkIoModel::Multiplexing)
        {
#ifdef MacroWindows
	        const auto iocp = CreateIoCompletionPort(
                INVALID_HANDLE_VALUE, nullptr, 0, params.ThreadCount);
            while (true)
            {
                sockaddr_in clientAddr{};
                auto addrLen = sizeof clientAddr;
	            auto client = WSAAccept(
                    serverSocket,
                    reinterpret_cast<SOCKADDR*>(&clientAddr),
                    reinterpret_cast<int*>(&addrLen),
                    nullptr, NULL);
                if (client <= 0)
                {
                    continue;
                }
                CreateIoCompletionPort(
                    reinterpret_cast<HANDLE>(client), iocp, 0, 0);
                for (DWORD i = 0; i < params.ThreadCount; ++i)
                {
                    HANDLE thread = CreateThread(
                        nullptr, 
                        0,
                        ServerWorkerThread,
                        iocp,
                        0, NULL);
                    CloseHandle(thread);
                }
            	
                LPPER_IO_DATA pPerIoData = new PER_IO_DATA;
                ZeroMemory(pPerIoData, sizeof(PER_IO_DATA));

                //strcpy(pPerIoData->Buffer, "Welcome to the server!\r\n");

                pPerIoData->Overlapped.hEvent = WSACreateEvent();
                pPerIoData->Socket = client;
                pPerIoData->wsaBuf.buf = pPerIoData->Buffer;
                pPerIoData->wsaBuf.len = strlen(pPerIoData->Buffer);
                pPerIoData->BytesToSend = pPerIoData->wsaBuf.len;

                DWORD dwNumSent;
                if (WSASend(client, &(pPerIoData->wsaBuf), 1, &dwNumSent, 0, &(pPerIoData->Overlapped), NULL) == SOCKET_ERROR)
                {
                    if (WSAGetLastError() != WSA_IO_PENDING)
                    {
                        delete pPerIoData;
                    }
                }
            }
#else
            epoll_event events[4096] = {0};
            auto epollFd = epoll_create(4096);
            std::unordered_map<SocketType, sockaddr_in> addrs{};
            Thread::Channel<SocketType> msg{};
            static const auto SendFunc = Response::DefaultSendFunc;
            static const std::any SendFuncArgs = {};
            static const auto RecvFunc = Request::DefaultRecvFunc;
            static const std::any RecvFuncArgs = {};
            for (auto i = 0; i < params.ThreadCount; ++i)
            {
                threadPool.emplace_back([&](const auto id)
                {
                    while (true)
                    {
                        auto client = msg.Read();
                        bool alive;
                        try
                        {
                            WorkParams workParams
                            {
                                client,
                                addrs.at(client),
                                true,
                                RecvFunc,
                                RecvFuncArgs,
                                SendFunc,
                                SendFuncArgs
                            };
                            alive = Work(workParams);
                        }
                        catch (const KappaJukoException& ex)
                        {
                            alive = false;
                            LogError(
                                "\nException in thread \"", Convert::ToString(id), "\" java.lang.NullPointerException: ", ex.what(),
                                "\n    at ", MacroFunctionName, "(" __FILE__ ":" MacroLine ")\n");
                        }
                        if (!alive)
                        {
                            CloseSocket(client);
                            epoll_ctl(epollFd, EPOLL_CTL_DEL, client, nullptr);
                        }
                    }
                }, i);
            }
            addEvent(epollFd, serverSocket, EPOLLIN);
            while (true)
            {
                auto res = epoll_wait(epollFd, events, 4096, -1);
                for (decltype(res) i = 0; i < res; ++i)
                {
                    auto fd = events[i].data.fd;
                    if (fd == serverSocket && (events[i].events & EPOLLIN))
                    {
                        sockaddr_in clientAddr{};
                        auto addrLen = sizeof clientAddr;
                        const auto client = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), reinterpret_cast<socklen_t*>(&addrLen));
                        if (client <= 0) continue;
                        //fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK);
                        addEvent(epollFd, client, EPOLLIN | EPOLLET);
                        addrs[client] = clientAddr;
                    }
                    else if (events[i].events & EPOLLIN)
                    {
                        msg.Write(fd);
                    }
                }
            }
#endif
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

    static bool IndexOfBody(const std::filesystem::path& path, std::string& page, const bool imageBoard = false)
    {
        std::unordered_set<std::string_view> imageTypes{ ".png", ".jpg", ".jpeg", ".webp", ".gif" };
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
            else if (file->is_directory() && file->path().filename() != ".__th__")
            {
                dirs.emplace(fnu8, fn);
            }
        }
        String::StringCombine(
            page, "<a href=\"../\">../</a><br/>");
        while (!dirs.empty())
        {
            const auto& [fnu8, fn] = dirs.top();
            String::StringCombine(
                page, "<a href=\"", fn, "/\">", fnu8, "/</a><br/>");
            dirs.pop();
        }
        if (!files.empty())
        {
            String::StringCombine(
                page,
                "<hr>"
                "<table>"
                "<tr><th>File Name</th><th>Size</th></tr>");
            while (!files.empty())
            {
                const auto& [fnu8, fn, sz] = files.top();
                String::StringCombine(
                    page, "<tr><td><a href=\"", fn, "\">", fnu8, "</a></td><td>", Convert::ToString(sz), "</td></tr>");
                files.pop();
            }
            String::StringCombine(
                page, "</table>");
        }
        if (!images.empty())
        {
            String::StringCombine(
                page,
                "<hr>"
                "<ul>");
            while (!images.empty())
            {
                String::StringCombine(
                    page, "<li><img src=\".__th__/", images.top(), ".png\"/></li>");
                images.pop();
            }
            String::StringCombine(
                page, "</ul>");
        }
        return true;
    }

    struct IndexOfFuncParams
    {
        const std::filesystem::path& Path;
        const bool KeepAlive;
        const bool ImageBoard;
        bool HeadOnly;
        decltype(Response::SendFunc) SendFunc;
        std::any SendFuncArgs;
    };
	
    static bool IndexOf(const IndexOfFuncParams& params, Request& request, const Response& forbiddenResponse)
    {
        const auto client = request.Client;
        const auto indexOfPath = request.Path();
        std::string indexOfPage{};
    	String::StringCombine(
        indexOfPage,
            "<!DOCTYPE html>"
            "<html>"
            "<head><title>Index of " , indexOfPath , "</title>"
            "<meta charset=\"utf-8\"/>"
            "<style type=\"text/css\">"
            "body {"
            "background: #222;"
            "color: #ddd;"
            "font-family: " R"("Lato", "Hiragino Sans GB", "Source Han Sans SC", "Source Han Sans CN", "Noto Sans CJK SC", "WenQuanYi Zen Hei", "WenQuanYi Micro Hei", "微软雅黑", sans-serif;)"
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
            "}"
            "</style>");

        if (params.ImageBoard)
        {
        	String::StringCombine(
            indexOfPage,
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
                "</script>");
        }
        String::StringCombine(
            indexOfPage,
            "</head>"
            "<body>"
            "<h1>Index of ", indexOfPath, "</h1><hr>");

        if (!IndexOfBody(params.Path, indexOfPage, params.ImageBoard))
        {
            return forbiddenResponse.Send(client, params.HeadOnly);
        }
        String::StringCombine(
            indexOfPage, "</body></html>");
        auto indexOf = Response::FromHtml(params.KeepAlive, indexOfPage, params.SendFunc, params.SendFuncArgs, 200);
        indexOf.Finish();
        return indexOf.Send(client, params.HeadOnly);
    }

	template<typename T>
    struct FuncAndArgs
    {
        T Func;
        std::any Args;
    };

    static auto RangeResponseFunc(const SocketType client, const decltype(Response::SendFunc) sendFunc,
        const std::any& sendFuncArgs, const std::any& args)
    {
        const auto& [path, start, diff] =
            std::any_cast<std::tuple<std::filesystem::path, std::uint64_t, std::uint64_t>>(args);
        std::ifstream fs(path, std::ios_base::in | std::ios_base::binary);
        char buf[4096];
        std::uint64_t count = 0;
        fs.seekg(start);
        while (count < diff)
        {
#ifdef MacroWindows
#undef min
#endif
            fs.read(buf, std::min(static_cast<decltype(diff)>(4096), diff - count));
            const auto counted = fs.gcount();
            IfFalseReturnFalse(sendFunc(client, buf, counted, sendFuncArgs));
            count += counted;
        }
        return true;
    };
	
    static bool RangeResponse(
        const std::filesystem::path& path, const SocketType client, const FuncAndArgs<decltype(Response::SendFunc)>& sendFunc,
        const std::string& rangeHeader, const bool keepAlive, const bool headOnly = false)
    {
        const auto fileSize = file_size(path);
        const auto range = rangeHeader.substr(5);
        std::string::size_type comPos = 0;
        do
        {
            auto spPos = range.find('-', comPos);
            auto start = Convert::FromString<uint64_t>(range.substr(comPos + 1, spPos - comPos - 1));
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
                    end = Convert::FromString<uint64_t>(range.substr(spPos + 1));
                }
            }
            else
            {
                end = Convert::FromString<uint64_t>(range.substr(spPos + 1, comPos - spPos - 1));
            }
            if ((start >= fileSize) || (end >= fileSize))
            {
                Response notSatisfiable(keepAlive, sendFunc.Func, sendFunc.Args, 416);
                std::string cr("*/");
                cr.append(Convert::ToString(fileSize));
                notSatisfiable.Headers[WebUtility::HttpHeadersKey::ContentRange] = cr;
                notSatisfiable.Finish();
                IfFalseReturnFalse(notSatisfiable.Send(client))
            }
            else
            {
                const auto diff = end - start + 1;
                Response resp(keepAlive, sendFunc.Func, sendFunc.Args, 206);
                resp.Headers[WebUtility::HttpHeadersKey::AcceptRanges] = "bytes";
                resp.Headers[WebUtility::HttpHeadersKey::ContentLength] = std::to_string(diff);
                std::string contextRange{};
                String::StringCombine(
                    contextRange, "bytes ", Convert::ToString(start), "-", Convert::ToString(end), "/", Convert::ToString(fileSize));
                resp.Headers[WebUtility::HttpHeadersKey::ContentRange] = contextRange;
                resp.SendBodyArgs = 
                    std::tuple<std::filesystem::path, std::uint64_t, std::uint64_t>(
                        path, start, diff);
                resp.SendBody = RangeResponseFunc;
                resp.Finish();
                IfFalseReturnFalse(resp.Send(client, headOnly))
            }
        } while (comPos != std::string::npos);
        return true;
    }

    static auto WorkStaticPage(
        const std::filesystem::path& path,
        const std::uint16_t code,
        const bool keepAlive,
        const decltype(Response::SendFunc) sendFunc,
        const std::any& sendFuncArgs)
    {
        if (path.empty())
        {
            return Response::FromStatusCodeHtml(keepAlive, sendFunc, sendFuncArgs, code);
        }
        auto resp = Response::FromFile(keepAlive, path, sendFunc, sendFuncArgs, code);
        resp.Finish();
        return resp;
    };
	
    bool HttpServer::Work(const WorkParams& workParams)
    {
        Request req(workParams.Client, workParams.Address, workParams.RecvFunc, workParams.RecvFuncArgs);
        #define ForbiddenResp WorkStaticPage(params.ForbiddenResponse, 403, workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs)
		#define NotFoundResp WorkStaticPage(params.NotFoundResponse, 404, workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs)
        try
        {
            if (params.LogFileLevel >= LogLevel::Info)
            {
                LogInfo(" [", req.Ip(), ":", Convert::ToString(req.Port()), "]\n", req.Raw);
            }
            if (req.Raw.empty())
            {
            	IfFalseReturnFalse(workParams.SendFunc(workParams.Client, req.Raw.c_str(), req.Raw.length(), workParams.SendFuncArgs))
                return workParams.KeepAlive;
            }
            if (params.CgiHook.has_value())
            {
                const auto cgi = (**params.CgiHook)(req, workParams.SendFunc, workParams.SendFuncArgs, workParams.KeepAlive, params);
                if (cgi.has_value())
                {
                    return *cgi;
                }
            }
            const auto headOnly = req.Method() == WebUtility::HttpMethod::HEAD;
            const auto rawPath = req.Path();
            if (params.LogFileLevel >= LogLevel::Debug)
            {
                LogDebug(" [", req.Ip(), ":", Convert::ToString(req.Port()), "]\n", rawPath);
            }
            std::string::size_type pos = 0;
            for (const auto rawPathLength = rawPath.length(); pos < rawPathLength; ++pos)
            {
	            if (const auto x = rawPath[pos]; !(x == '/' || x == '\\'))
	            {
		            break;
	            }
            }
            auto realPath = params.RootPath / std::filesystem::u8path(rawPath.substr(pos));
            if (realPath.lexically_normal().u8string().find(params.RootPath.lexically_normal().u8string()) != 0)
            {
                IfFalseReturnFalse(Response::FromStatusCodeHtml(workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs, 400).Send(workParams.Client, headOnly))
                return workParams.KeepAlive;
            }
            switch (req.Method())
            {
            case WebUtility::HttpMethod::GET:
            case WebUtility::HttpMethod::POST:
            case WebUtility::HttpMethod::HEAD:
                if (exists(realPath))
                {
                    if (is_directory(realPath))
                    {
                        if (params.AutoIndexMode)
                        {
                            if (rawPath[rawPath.length() - 1] != '/')
                            {
                                Response moveResp(workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs, 301);
                                moveResp.Headers[WebUtility::HttpHeadersKey::Location] = rawPath + "/";
                                moveResp.Finish();
                                IfFalseReturnFalse(moveResp.Send(workParams.Client, headOnly))
                                return workParams.KeepAlive;
                            }
                            IndexOfFuncParams indexOfFuncParams
                            {
                                realPath,
                                workParams.KeepAlive,
                                params.ImageBoard,
                            	headOnly,
                                workParams.SendFunc,
                            	workParams.SendFuncArgs
                            };
                            if (!IndexOf(indexOfFuncParams, req, ForbiddenResp))
                            {
                                return false;
                            }
                            return workParams.KeepAlive;
                        }
                        auto found = false;
                        auto pos = params.IndexPages.begin();
                        auto end = params.IndexPages.end();
                        for (; pos != end; ++pos)
                        {
	                        if(exists(realPath / *pos))
	                        {
                                found = true;
	                        	break;
	                        }
                        }
                        if (!found)
                        {
                            IfFalseReturnFalse(ForbiddenResp.Send(workParams.Client, headOnly))
                            return workParams.KeepAlive;
                        }
                        realPath /= *pos;
                    }
                    if (is_regular_file(realPath))
                    {
                        const auto ifNoneMatch = req.Header(WebUtility::HttpHeadersKey::IfNoneMatch);
                        const auto ifModified = req.Header(WebUtility::HttpHeadersKey::IfModifiedSince);
                        if (ifNoneMatch.has_value())
                        {
                            if (WebUtility::ETag(WebUtility::FileLastModified(realPath), file_size(realPath)) == *ifNoneMatch)
                            {
                                Response resp(workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs, 304);
                                resp.Headers[WebUtility::HttpHeadersKey::ETag] = *ifNoneMatch;
                                resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";
                                if (ifModified.has_value())
                                {
                                    resp.Headers[WebUtility::HttpHeadersKey::LastModified] = *ifModified;
                                }
                                resp.Finish();
                                IfFalseReturnFalse(resp.SendHead(workParams.Client))
                                return workParams.KeepAlive;
                            }
                        }
                        else if (ifModified.has_value())
                        {
                            const auto lm = WebUtility::ToGmtString(WebUtility::FileLastModified(realPath));
                            if (lm == *ifModified)
                            {
                                Response resp(workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs, 304);
                                resp.Headers[WebUtility::HttpHeadersKey::LastModified] = *ifModified;
                                resp.Headers[WebUtility::HttpHeadersKey::CacheControl] = "max-age=31536000";
                                resp.Finish();
                                IfFalseReturnFalse(resp.SendHead(workParams.Client))
                                return workParams.KeepAlive;
                            }
                        }
                        auto rangeAllow = true;
                        const auto ifRange = req.Header(WebUtility::HttpHeadersKey::IfRange);
                        if (ifRange.has_value())
                        {
                            const auto last = WebUtility::FileLastModified(realPath);
                            if (WebUtility::ETag(last, file_size(realPath)) != *ifRange
                                && WebUtility::ToGmtString(last) != *ifRange)
                            {
                                rangeAllow = false;
                            }
                        }
                        const auto rawRange = req.Header(WebUtility::HttpHeadersKey::Range);
                        if (rangeAllow && rawRange.has_value())
                        {
                            FuncAndArgs<decltype(Response::SendFunc)> sf
                            {
                                workParams.SendFunc,
                                workParams.SendFuncArgs
                            };
	                        IfFalseReturnFalse(RangeResponse(realPath, workParams.Client, sf, *rawRange, workParams.KeepAlive, headOnly))
                            return workParams.KeepAlive;
                        }
                        auto resp = Response::FromFile(workParams.KeepAlive, realPath, workParams.SendFunc, workParams.SendFuncArgs, 200);
                        auto ext = realPath.extension().u8string();
                        String::ToLower(ext);
                        auto pos = WebUtility::HttpContentType.find(ext);
                        if (pos != WebUtility::HttpContentType.end())
                        {
                            resp.Headers[WebUtility::HttpHeadersKey::ContentType] = pos->second;
                        }
                        resp.Finish();
                        IfFalseReturnFalse(resp.Send(req.Client, headOnly))
                        return workParams.KeepAlive;
                    }
                    IfFalseReturnFalse(ForbiddenResp.Send(workParams.Client, headOnly))
                    return workParams.KeepAlive;
                }
                IfFalseReturnFalse(NotFoundResp.Send(workParams.Client, headOnly))
                return workParams.KeepAlive;
            case WebUtility::HttpMethod::PUT:
            case WebUtility::HttpMethod::DELETE:
            case WebUtility::HttpMethod::CONNECT:
            case WebUtility::HttpMethod::OPTIONS:
            case WebUtility::HttpMethod::TRACE:
            case WebUtility::HttpMethod::PATCH:
                IfFalseReturnFalse(Response::FromStatusCodeHtml(workParams.KeepAlive, workParams.SendFunc, workParams.SendFuncArgs, 501).Send(workParams.Client))
                return workParams.KeepAlive;
            }
            return workParams.KeepAlive;
        }
        catch (const KappaJukoException&)
        {
            throw;
        }
        catch (const std::exception& ex)
        {
           LogError(
                "[", req.Ip(), ":", Convert::ToString(req.Port()), "] [Unknown Error] [", ex.what(), "]\n", req.Raw);
            throw;
        }
    }
	
    void HttpServer::DefaultLogThread(const LogLevel Level, const std::filesystem::path& File, const bool Console)
    {
        std::ofstream fs{};
        while (true)
        {
            const auto [l, msg] = Log.Chan.Read();
            const auto [t, i, s] = msg;
            if (l <= Level)
            {
                auto time = std::chrono::system_clock::to_time_t(t);
                tm local{};
                Time::Local(&local, &time);
                std::ostringstream buf{};
                buf << std::put_time(&local, "[%F %X] [");
                const auto log = String::StringCombineNew(buf.str(), ToString(l), "] [0x", String::FromStreamNew(i, std::hex), "] ", s);
                if (Console)
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
                if (!File.empty())
                {
                    fs.open(File, std::ios::app | std::ios::binary);
                    fs << log << "\n";
                    fs.close();
                }
            }
        }
    }
}
