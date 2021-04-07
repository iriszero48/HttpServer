#pragma once

#include <condition_variable>
#include <mutex>
#include <list>

namespace Thread
{
    template<typename Func>
    struct Synchronize
    {
        std::mutex Mtx{};
        Func F;

        explicit Synchronize(const Func& func) : F(func) {}

        template<typename ...Args>
        decltype(auto) operator()(Args&&...args)
        {
            std::lock_guard<decltype(Mtx)> lock(Mtx);
            return F(std::forward<Args>(args)...);
        }
    };

    template<typename T>
    class Channel
    {
    public:
        void Write(const T& data)
        {
            std::unique_lock<std::mutex> lock(mtx);
            buffer.push_back(data);
            lock.unlock();
            cv.notify_all();
        }

        T Read()
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&]() { return !buffer.empty(); });
            const auto item = buffer.front();
            buffer.pop_front();
            return item;
        }

        [[nodiscard]] auto Length() const
        {
            return buffer.size();
        }

    private:
        std::list<T> buffer{};
        std::mutex mtx{};
        std::condition_variable cv{};
    };
}
