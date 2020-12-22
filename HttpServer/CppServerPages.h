#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <functional>
#include <utility>

#include "HttpServer.h"

namespace CppServerPages
{
	class CppServerPagesException: public KappaJuko::KappaJukoException { using KappaJukoException::KappaJukoException; };
	
	struct Session
	{
		std::optional<std::string> User;
		decltype(std::chrono::system_clock::now()) LastVisitTime;
	};

	template<typename K, typename V>
	class Database
	{
	public:
		using Key = K;
		using Value = V;
		using SerializeFunc = std::function<void(const K& key, const V& value)>;
		using SerializeFuncOpt = std::optional<SerializeFunc>;
		using UnserializeFunc = std::function<void(std::unordered_map<K, V>& key)>;
		using UnserializeFuncOpt = std::optional<UnserializeFunc>;

		explicit Database(const UnserializeFuncOpt& unserialize = {}, SerializeFuncOpt serialize = {}) :
			serialize(std::move(serialize))
		{
			if (unserialize.has_value())
			{
				unserialize->operator()(db);
			}
		}

		std::optional<V> Get(const K& key)
		{
			const auto pos = db.find(key);
			if (pos == db.end())
			{
				return std::nullopt;
			}
			return pos->second;
		}

		void Set(const K& key, const V& value)
		{
			std::lock_guard<std::mutex> lck(lock);
			db[key] = value;
			if (serialize.has_value())
			{
				serialize->operator()(key, value);
			}
		}

	private:
		std::unordered_map<K, V> db{};
		std::mutex lock{};
		std::optional<SerializeFunc> serialize{};
	};

	static Database<std::string, Session> Sessions{};

	std::string GenerateSessionId();
}
