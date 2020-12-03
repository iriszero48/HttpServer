#pragma once

#include <functional>
#include <optional>
#include <thread>
#include <utility>

#include "Arguments.h"

#if (defined _WIN32 || _WIN64)
#define __Kappa_Juko__Windows__
#else
#define __Kappa_Juko__Linux__
#endif

#ifdef __Kappa_Juko__Windows__

#include <WinSock2.h>

#else

#include <sys/socket.h>

#endif

namespace KappaJuko
{
	constexpr std::string_view ServerName = "KappaJuko";
	constexpr std::string_view Version = "1.0.0";

	using SocketType =
#ifdef __Kappa_Juko__Windows__
		SOCKET;
#else
		int;
#endif
	
	ArgumentOptionHpp(NetworkIoModel, Blocking, Multiplexing)
	ArgumentOptionHpp(HttpMethod, GET, POST)
	
	class Request
	{
	public:
		HttpMethod Method;
		
		explicit Request(SocketType sock, const sockaddr_in&);

		std::string Url();
		std::string Header(const std::string& param);
		std::string Get(const std::string& param);
		std::string Post(const std::string& param);
	private:
		std::string raw;
		std::string rawGet;
		std::string rawPost;
		
		std::string ip;
		uint16_t port;
		
		std::optional<std::string> url;
		std::optional<std::unordered_map<std::string, std::string>> headerData;
		std::optional<std::unordered_map<std::string, std::string>> getData;
		std::optional<std::unordered_map<std::string, std::string>> postData;
	};
	
	struct LauncherParams
	{
		std::string_view RootPath;
		uint16_t Port = 80;
		uint16_t ThreadCount = 1;
		NetworkIoModel IoModel = NetworkIoModel::Multiplexing;
		bool AutoIndexMode = false;
		bool NotFoundRedirect = false;
		std::optional<std::function<bool(const Request&)>> CgiHook = std::nullopt;

		[[nodiscard]] static LauncherParams FromArgs(int args, char** argv);
	};

	class KappaJukoException : public std::runtime_error { using std::runtime_error::runtime_error; };
	class InitializationException : public KappaJukoException { using KappaJukoException::KappaJukoException; };
	class CreateSocketException final : public InitializationException { using InitializationException::InitializationException; };
	class BindPortException final : public InitializationException { using InitializationException::InitializationException; };
	
	class HttpServer
	{
	public:
		explicit HttpServer(LauncherParams params) : params(std::move(params)) {}
		~HttpServer() = default;

		HttpServer() = delete;
		HttpServer(const HttpServer& httpServer) = delete;
		HttpServer(HttpServer&& httpServer) = delete;
		HttpServer operator=(const HttpServer& httpServer) = delete;
		HttpServer operator=(HttpServer&& httpServer) = delete;
		
		void Init();
		void Run();
		void Close() const;
	private:
		LauncherParams params;
		SocketType serverSocket;
		std::vector<std::thread> threadPool;

		void Work(SocketType client, const sockaddr_in& address);
	};
}
