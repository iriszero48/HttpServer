#pragma once

namespace Function
{
    template <typename G, typename F>
    decltype(auto) Compose(G&& g, F&& f)
	{
        return [=](auto&& ...x) { return f(g(x...)); };
    }
}
