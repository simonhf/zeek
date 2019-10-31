// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#if defined(HAVE_EPOLL_H)
#include <sys/epoll.h>
#include <sys/timerfd.h>
#elif defined(HAVE_KQUEUE)
#include <sys/event.h>
#else
#include <poll.h>
#endif

#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>

namespace iosource {

class IOSource;
class PktSrc;
class PktDumper;

/**
 * Singleton class managing all IOSources.
 */
class Manager {
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Registers an IOSource with the manager. If the source is already
	 * registered, the method will update its *dont_count* value but not
	 * do anything else.
	 *
	 * @param src The source. The manager takes ownership.
	 *
	 * @param dont_count If true, this source does not contribute to the
	 * number of IOSources returned by Size().  The effect is that if all
	 * sources except for the non-counting ones have gone dry, processing
	 * will shut down.
	 */
	void Register(IOSource* src, bool dont_count = false);

	/**
	 * Returns the number of registered and still active sources,
	 * excluding those that are registered as \a dont_cont.
	 */
	int Size() const	{ return sources.size() - dont_counts; }

	typedef std::list<PktSrc *> PktSrcList;

	/**
	 * Returns a list of all registered PktSrc instances. This is a
	 * subset of all registered IOSource instances.
	 */
	const PktSrcList& GetPktSrcs() const	{ return pkt_srcs; }

	/**
	 * Terminate all processing immediately by removing all sources (and
	 * therefore now returning a Size() of zero).
	 */
	void Terminate()	{ RemoveAll(); }

	/**
	 * Opens a new packet source.
	 *
	 * @param path The interface or file name, as one would give to Bro \c -i.
	 *
	 * @param is_live True if \a path represents a live interface, false
	 * for a file.
	 *
	 * @return The new packet source, or null if an error occured.
	 */
	PktSrc* OpenPktSrc(const std::string& path, bool is_live);

	/**
	 * Opens a new packet dumper.
	 *
	 * @param path The file name to dump into.
	 *
	 * @param append True to append if \a path already exists.
 	 *
	 * @return The new packet dumper, or null if an error occured.
	 */
	PktDumper* OpenPktDumper(const std::string& path, bool append);

	std::set<IOSource*> FindReadySources(bool& timer_expired);

	void RegisterFd(int fd, IOSource* src);
	void UnregisterFd(int fd);

private:

	void Register(PktSrc* src);
	void RemoveAll();

	void InitQueue();
	bool Poll(std::set<IOSource*>& ready, double timeout, IOSource* timeout_src);

	int dont_counts;

	struct Source {
		IOSource* src;
		bool dont_count;
	};

	typedef std::list<Source*> SourceList;
	SourceList sources;

	typedef std::list<PktDumper *> PktDumperList;

	PktSrcList pkt_srcs;
	PktDumperList pkt_dumpers;

	int event_queue;
	std::map<int, IOSource*> fd_map;

#if defined(HAVE_EPOLL_H)
	std::vector<epoll_event> events;
#elif defined(HAVE_KQUEUE)
	// This is only used for the output of the call to kqueue in FindReadySources().
	// The actual events are stored as part of the queue.
	std::vector<struct kevent> events;
#else
	// Fall back to regular poll() if we don't have kqueue or epoll.
	std::vector<pollfd> events;
#endif
};

}

extern iosource::Manager* iosource_mgr;
