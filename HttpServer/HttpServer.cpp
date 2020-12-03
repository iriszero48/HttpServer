#include <filesystem>
#include <unordered_map>
#include <iostream>

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
	ArgumentOptionCpp(NetworkIoModel, Blocking, Multiplexing)
	ArgumentOptionCpp(HttpMethod, GET, POST)

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
		args.Add(rootPath);
		args.Add(port);
		args.Add(threadCount);
		args.Add(ioModel);
		args.Add(autoIndexMode);
		args.Add(notFoundRedirect);
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
				ArgumentsValue(notFoundRedirect)
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
		if (bind(serverSocket, reinterpret_cast<const sockaddr*>(&serverSockAddr), sizeof serverSockAddr) < 0)
		{
			KappaJukoThrow(BindPortException, "Can't bind");
		}
		threadPool = std::vector<std::thread>(params.ThreadCount);
		
		listen(serverSocket, 10000);
	}
	
	void HttpServer::Run()
	{
		if (params.IoModel == NetworkIoModel::Blocking)
		{
			std::generate(threadPool.begin(), threadPool.end(), [&]()
			{
				return std::thread([&]()
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
						Work(client, clientAddr);
					}
				});
			});
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
	
	void HttpServer::Work(const SocketType client, const sockaddr_in& address)
	{
		const Request req(client, address);
		if (params.CgiHook.has_value())
		{
			if (!params.CgiHook.value()(req))
			{
				
			}
		}
	}
}
