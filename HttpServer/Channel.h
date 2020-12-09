#pragma once

#include <condition_variable>
#include <mutex>
#include <list>

template<typename T>
class Channel
{
public:
    void Write(const T& data)
    {
        std::unique_lock<std::mutex> lock(mtx);
        buffer.push_back(data);
        avail = true;
        cv.notify_all();
    }

    T Read()
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() { return avail; });
        const auto item = buffer.front();
        buffer.pop_front();
        avail = false;
        return item;
    }

private:
    std::list<T> buffer{};
    std::mutex mtx{};
    std::condition_variable cv{};
    bool avail = false;
};
