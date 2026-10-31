// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This is advanced C++ "plumbing", not Bitcoin rules. You can skip it on a
// first read. It lets one part of the program announce "something happened"
// to any other parts that want to know, without the parts knowing about
// each other. It is like a group chat:
//   - a SIGNAL is the group chat, for one kind of event, such as "a
//     transaction in my wallet changed" (see NotifyTransactionChanged in
//     wallet/wallet.h),
//   - connect() joins the chat with a CALLBACK: a function to run each time
//     the event happens,
//   - the CONNECTION it returns is your membership, and disconnect() leaves,
//   - calling the signal like a function, signal(...), sends the message:
//     every connected callback runs.
//
// A 2026 upstream change (merged into Comment House on 2026-10-31) fixed WHEN
// a callback is destroyed. Before, a disconnected callback stayed in memory
// until the next connect() cleaned it up. Now it is destroyed as soon as you
// disconnect, or, if it is running at that moment, as soon as it finishes.
// A callback often holds on to other objects, so freeing it promptly
// matters. The detail namespace and connection::liveness below are the parts
// that changed.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_UTIL_BTCSIGNALS_H
#define BITCOIN_UTIL_BTCSIGNALS_H

#include <sync.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

/**
 * btcsignals is a simple mechanism for signaling events to multiple subscribers.
 * It is api-compatible with a minimal subset of boost::signals2.
 *
 * Rather than using a custom slot type, and the features/complexity that they
 * imply, std::function is used to store the callbacks. There is no automatic
 * tracking of objects the callbacks refer to, so callers need to disconnect
 * callbacks before those objects are destroyed.
 *
 * Like boost::signals2, disconnecting a connection destroys its callback
 * object, or if the callback is running at the time, destroys it when the
 * call returns. Callbacks that are never disconnected are destroyed with the
 * signal.
 *
 * All usage is thread-safe except for interacting with a connection while
 * copying/moving it on another thread.
 */

namespace btcsignals {

/// The default combiner, which only returns void.
// COMMENT HOUSE: "Combiners" decide what calling a signal returns. null_value
// returns nothing. any_of returns true if at least one callback returned
// true.
class null_value
{
public:
    using result_type = void;
};

/// A combiner, which checks if at least one callback returned true.
class any_of
{
public:
    // This is the only supported combiner with a non-void return type. As
    // such, its behavior is embedded into the signal functor.
    using result_type = bool;
};

template <typename Signature, typename Combiner = null_value>
class signal;

// COMMENT HOUSE: detail::atomic_shared_ptr (new upstream, 2026). Background:
//   - A shared_ptr is a pointer that counts how many owners an object has.
//     The object is destroyed automatically when the last owner lets go.
//   - "atomic" means several threads (parts of the program running at the
//     same time) can read and replace it safely, without locks.
// C++20 provides std::atomic<std::shared_ptr<T>> for this, but some
// standard libraries do not have it yet. The #ifdef checks whether it
// exists. If not, this small stand-in class does the same job using the
// older std::atomic_load and std::atomic_store functions.
namespace detail {
#ifdef __cpp_lib_atomic_shared_ptr
template <typename T>
using atomic_shared_ptr = std::atomic<std::shared_ptr<T>>;
#else
//! Substitute for the C++20 std::atomic<std::shared_ptr<T>> specialization on
//! standard libraries that do not provide it yet (feature-test macro
//! __cpp_lib_atomic_shared_ptr), implemented with the C++11 atomic_load and
//! atomic_store overloads for shared_ptr. Only the members used here are
//! provided.
template <typename T>
class atomic_shared_ptr
{
    std::shared_ptr<T> m_ptr;

public:
    explicit atomic_shared_ptr(std::shared_ptr<T> ptr) noexcept : m_ptr{std::move(ptr)} {}
    atomic_shared_ptr(const atomic_shared_ptr&) = delete;
    atomic_shared_ptr& operator=(const atomic_shared_ptr&) = delete;
    std::shared_ptr<T> load() const noexcept { return std::atomic_load(&m_ptr); }
    void store(std::shared_ptr<T> ptr) noexcept { std::atomic_store(&m_ptr, std::move(ptr)); }
};
#endif
} // namespace detail

/*
 * State object representing the liveness of a registered callback.
 * signal::connect() returns an enabled connection which can be held and
 * disabled in the future.
 */
// COMMENT HOUSE: connection, your "membership" in a signal.
// Inside it, liveness holds the callback in an atomic_shared_ptr. Since the
// 2026 change:
//   - disconnect() replaces it with nullptr (empty). If nobody else is using
//     the callback, it is destroyed right away.
//   - connected() just asks "is the pointer still non-empty?".
//   - While a signal is running a callback it holds its own copy of the
//     pointer, so a callback that is disconnected mid-run is only destroyed
//     once that run finishes.
class connection
{
    template <typename Signature, typename Combiner>
    friend class signal;
    /**
     * Track liveness. Also serves as a tag for the constructor used by signal.
     */
    class liveness
    {
        friend class connection;

        //! Callback object, type-erased so connection does not depend on the
        //! signal type, and set to null by disconnect(). Signal invocation
        //! holds a reference to it while calling it, so a callback
        //! disconnected during a call is destroyed when the call returns.
        detail::atomic_shared_ptr<const void> m_callback;

        void disconnect() { m_callback.store(nullptr); }

    protected:
        explicit liveness(std::shared_ptr<const void> callback) : m_callback{std::move(callback)} {}

        std::shared_ptr<const void> load() const { return m_callback.load(); }

    public:
        bool connected() const { return load() != nullptr; }
    };

    /**
     * connections have shared_ptr-like copy and move semantics.
     */
    std::shared_ptr<liveness> m_state{};

    /**
     * Only a signal can create an enabled connection.
     */
    explicit connection(std::shared_ptr<liveness>&& state) : m_state{std::move(state)}{}

public:
    /**
     * The default constructor creates a connection with no associated signal
     */
    constexpr connection() noexcept = default;

    /**
     * If a callback is associated with this connection, prevent it from being
     * called in the future.
     *
     * If a connection is disabled as part of a signal's callback function, it
     * will _not_ be executed in the current signal invocation.
     *
     * The callback object is destroyed here (or when the last concurrently
     * executing invocation of it completes). The empty holder entry is not
     * removed from the owning signal; it is garbage collected in
     * signal::connect().
     */
    void disconnect()
    {
        if (m_state) {
            m_state->disconnect();
        }
    }

    /**
     * Returns true if this connection was created by a signal and has not been
     * disabled.
     */
    bool connected() const
    {
        return m_state && m_state->connected();
    }
};

/*
 * RAII-style connection management
 */
// COMMENT HOUSE: scoped_connection disconnects automatically when it is
// destroyed. This pattern is called RAII ("resource acquisition is
// initialisation"): tie cleanup to an object's lifetime, so it cannot be
// forgotten.
class scoped_connection
{
    connection m_conn;

public:
    explicit scoped_connection(connection rhs) noexcept : m_conn{std::move(rhs)} {}

    scoped_connection(scoped_connection&&) noexcept = default;

    /**
     * For simplicity, disable copy construction and copy/move assignment.
     */
    scoped_connection& operator=(scoped_connection&&) = delete;
    scoped_connection& operator=(const scoped_connection&) = delete;
    scoped_connection(const scoped_connection&) = delete;

    void disconnect()
    {
        m_conn.disconnect();
    }

    ~scoped_connection()
    {
        disconnect();
    }
};

/*
 * Functor for calling zero or more connected callbacks
 */
template <typename Signature, typename Combiner>
// COMMENT HOUSE: signal, the "group chat" itself. It keeps a list
// (m_connections) of everyone connected. "Signature" is the type of
// callback it accepts, for example void(const Txid&).
class signal
{
    using function_type = std::function<Signature>;

    /*
     * Helper struct for maintaining a callback and its associated connection liveness
     */
    struct connection_holder : connection::liveness {
        template <typename Callable>
        explicit connection_holder(Callable&& callback)
            : liveness{std::make_shared<const function_type>(std::forward<Callable>(callback))}
        {
        }

        //! Return the callback, or null if disconnected. The callback stays
        //! alive while the returned pointer is held.
        std::shared_ptr<const function_type> callback() const
        {
            return std::static_pointer_cast<const function_type>(load());
        }
    };

    mutable Mutex m_mutex;

    std::vector<std::shared_ptr<connection_holder>> m_connections GUARDED_BY(m_mutex){};

public:
    using result_type = Combiner::result_type;

    constexpr signal() noexcept = default;
    ~signal() = default;

    /*
     * For simplicity, disable all moving/copying/assigning.
     */
    signal(const signal&) = delete;
    signal(signal&&) = delete;
    signal& operator=(const signal&) = delete;
    signal& operator=(signal&&) = delete;

    /*
     * Execute all enabled callbacks for the signal. Rather than allowing for
     * custom combiners, the behavior of any_of is hard-coded here.
     *
     * Callbacks which return void require special handling.
     *
     * In order to avoid locking during the callbacks, the list of callbacks is
     * cached before they are called. This allows a callback to call connect(),
     * but the newly connected callback will not be run during the current
     * signal invocation.
     *
     * Note that the parameters are accepted as universal references, though
     * they are not perfectly forwarded as that could cause a use-after-move if
     * more than one callback is enabled.
     */
    // COMMENT HOUSE: operator() runs the signal: signal(args...) calls every
    // connected callback with those arguments. It first copies the list while
    // holding the lock (m_mutex), then lets go of the lock before calling
    // anything, so a slow callback does not block everyone else. For each entry
    // it asks callback() for a pointer to the callback. If it gets one (not
    // disconnected), it calls it, and the pointer keeps the callback alive until
    // the call returns.
    template <typename... Args>
    [[nodiscard]] result_type operator()(Args&&... args) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::vector<std::shared_ptr<connection_holder>> connections;
        {
            LOCK(m_mutex);
            connections = m_connections;
        }
        if constexpr (std::is_void_v<result_type>) {
            static_assert(std::is_same_v<result_type, typename function_type::result_type>,
                          "Callback result type must be equal to the combiner result type (void).");
            for (const auto& connection : connections) {
                // Holding the callback pointer keeps the callback alive until
                // the call returns, even if it is disconnected concurrently.
                if (const auto callback{connection->callback()}) {
                    (*callback)(args...);
                }
            }
        } else {
            static_assert(std::is_same_v<Combiner, any_of>,
                          "only the any_of combiner is supported and hard-coded into this functor.");
            static_assert(std::is_same_v<result_type, typename function_type::result_type>,
                          "Callback result type must be equal to the combiner result type (bool).");
            result_type ret{false};
            for (const auto& connection : connections) {
                if (const auto callback{connection->callback()}) {
                    ret |= (*callback)(args...);
                }
            }
            return ret;
        }
    }

    /*
     * Connect a new callback to the signal. A forwarding callable accepts
     * anything that can be stored in a std::function.
     */
    template <typename Callable>
    connection connect(Callable&& func) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);

        // COMMENT HOUSE: connect(): first throw away list entries whose callbacks have
        // been disconnected, then add the new one and return its connection.
        // Garbage-collect disconnected connections to prevent unbounded growth
        std::erase_if(m_connections, [](const auto& holder) { return !holder->connected(); });

        const auto& entry = m_connections.emplace_back(std::make_shared<connection_holder>(std::forward<Callable>(func)));
        return connection(entry);
    }

    /*
     * Returns true if there are no enabled callbacks
     */
    [[nodiscard]] bool empty() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return std::ranges::none_of(m_connections, [](const auto& holder) {
            return holder->connected();
        });
    }
};

} // namespace btcsignals

#endif // BITCOIN_UTIL_BTCSIGNALS_H
