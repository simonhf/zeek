// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>

#include <algorithm>

#include "Manager.h"
#include "IOSource.h"
#include "Net.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"
#include "broker/Manager.h"

#include "util.h"

#define DEFAULT_PREFIX "pcap"

using namespace iosource;

Manager::~Manager()
	{
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		(*i)->src->Done();
		delete (*i)->src;
		delete *i;
		}

	sources.clear();

	for ( PktDumperList::iterator i = pkt_dumpers.begin(); i != pkt_dumpers.end(); ++i )
		{
		(*i)->Done();
		delete *i;
		}

	pkt_dumpers.clear();
	}

void Manager::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

std::set<IOSource*> Manager::FindReadySources(bool& timer_expired)
	{
	std::set<IOSource*> ready;

	// Remove sources which have gone dry. For simplicity, we only
	// remove at most one each time.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		if ( ! (*i)->src->IsOpen() )
			{
			(*i)->src->Done();
			delete *i;
			sources.erase(i);
			break;
			}

	// If there aren't any sources and exit_only_after_terminate is false, just
	// return an empty set of sources. We want the main loop to end.
	if ( Size() == 0 && ( ! BifConst::exit_only_after_terminate || terminating ) )
		return ready;

	double timeout = -1;
	IOSource* timeout_src = nullptr;
	timer_expired = false;

	// If we have an active source of data then find the next timeout value from
	// those sources. Start by getting the next timeout from the timer manager
	// since it's not an IOSource.
	// TODO: how do we handle multiple timer managers here?
	if ( ! pkt_srcs.empty() || broker_mgr->Active() )
		{
		timeout = timer_mgr->GetNextTimeout();

		for ( auto src : sources )
			{
			if ( src->src->IsOpen() )
				{
				double next = src->src->GetNextTimeout();
				if ( timeout == -1 || ( next >= 0.0 && next < timeout ) )
					{
					timeout = next;
					timeout_src = src->src;
					}
				}
			}
		}

	// If timeout ended up -1, set it to some nominal value just to keep the loop
	// from blocking forever. This is the case of exit_only_after_terminate when
	// there isn't anything else going on.
	if ( timeout == -1 )
		timeout = 100;
	else
		timeout *= 1000.0;

	// If the active packet source isn't live or the packet source is ready (i.e.
	// we're in pseudo-realtime mode and it's time for a packet), always insert
	// the packet source into the list of ready sources.
	if ( ! pkt_srcs.empty() && pkt_srcs.front()->IsOpen() && ! pkt_srcs.front()->IsLive() && pkt_srcs.front()->GetNextTimeout() == 0 )
		ready.insert(pkt_srcs.front());

	for ( auto pfd : poll_fds )
		pfd.revents = 0;

	// Poll will return the number of ready file descriptors, independent of the timeout.
	// That said, we need to keep track of whether there was a timer at zero so that we
	// don't end up with a case where
	int ret = poll(poll_fds.data(), poll_fds.size(), static_cast<int>(timeout));
	if ( ret == -1 )
		{
		// TODO: gotta do something else here
		perror("poll error");
		}
	else if ( ret == 0 )
		{
		// TODO: need a better way to handle the source that causes the timeout so
		// that just the timeout is processed instead of everything in the Process()
		// method of the source.
		if ( timeout_src )
			ready.insert(timeout_src->src);
		else
			// Setting this to true here but not returning a source causes net_run
			// to advance the time and process timers as normal.
			timer_expired = true;
		}
	else
		{
		// TODO: handle errors in revents in some way
		for ( auto pfd : poll_fds )
			{
			auto entry = fd_map.find(pfd.fd);
			if ( pfd.revents == pfd.events )
				ready.insert(entry->second);
			else if ( pfd.revents == POLLERR ||
				pfd.revents == POLLHUP ||
				pfd.revents == POLLNVAL )
				printf("Source %s returned an error from poll (0x%x)\n",
					entry->second->Tag(), pfd.revents);
			}
		}

	return ready;
	}

void Manager::Register(IOSource* src, bool dont_count)
	{
	// First see if we already have registered that source. If so, just
	// adjust dont_count.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		if ( (*i)->src == src )
			{
			if ( (*i)->dont_count != dont_count )
				// Adjust the global counter.
				dont_counts += (dont_count ? 1 : -1);

			return;
			}
		}

	src->Init();
	Source* s = new Source;
	s->src = src;
	s->dont_count = dont_count;
	if ( dont_count )
		++dont_counts;

	sources.push_back(s);
	}

void Manager::Register(PktSrc* src)
	{
	pkt_srcs.push_back(src);
	Register(src, false);
	}

static std::pair<std::string, std::string> split_prefix(std::string path)
	{
	// See if the path comes with a prefix telling us which type of
	// PktSrc to use. If not, choose default.
	std::string prefix;

	std::string::size_type i = path.find("::");
	if ( i != std::string::npos )
		{
		prefix = path.substr(0, i);
		path = path.substr(i + 2, std::string::npos);
		}

	else
		prefix= DEFAULT_PREFIX;

	return std::make_pair(prefix, path);
	}

PktSrc* Manager::OpenPktSrc(const std::string& path, bool is_live)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet sources of the requested prefix.

	PktSrcComponent* component = 0;

	std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();

	for ( std::list<PktSrcComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		PktSrcComponent* c = *i;

		if ( c->HandlesPrefix(prefix) &&
		     ((  is_live && c->DoesLive() ) ||
		      (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}


	if ( ! component )
		reporter->FatalError("type of packet source '%s' not recognized, or mode not supported", prefix.c_str());

	// Instantiate packet source.

	PktSrc* ps = (*component->Factory())(npath, is_live);
	assert(ps);

	if ( ! ps->IsOpen() && ps->IsError() )
		// Set an error message if it didn't open successfully.
		ps->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(), npath.c_str());

	Register(ps);
	return ps;
	}


PktDumper* Manager::OpenPktDumper(const string& path, bool append)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet dumpers of the requested prefix.

	PktDumperComponent* component = 0;

	std::list<PktDumperComponent*> all_components = plugin_mgr->Components<PktDumperComponent>();

	for ( std::list<PktDumperComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		if ( (*i)->HandlesPrefix(prefix) )
			{
			component = (*i);
			break;
			}
		}

	if ( ! component )
		reporter->FatalError("type of packet dumper '%s' not recognized", prefix.c_str());

	// Instantiate packet dumper.

	PktDumper* pd = (*component->Factory())(npath, append);
	assert(pd);

	if ( ! pd->IsOpen() && pd->IsError() )
		// Set an error message if it didn't open successfully.
		pd->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(), npath.c_str());

	pd->Init();
	pkt_dumpers.push_back(pd);

	return pd;
	}

void Manager::RegisterFd(int fd, IOSource* src)
	{
	if ( src == nullptr )
		return;

	auto entry = std::find_if(poll_fds.begin(), poll_fds.end(),
		[fd](const pollfd &entry) -> bool { return entry.fd == fd; });
	if ( entry == poll_fds.end() )
		{
		DBG_LOG(DBG_MAINLOOP, "Registering fd %d from %s", fd, src->Tag());
		pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN;
		poll_fds.push_back(pfd);
		fd_map[fd] = src;
		}
	}

void Manager::UnregisterFd(int fd)
	{
	auto entry = std::find_if(poll_fds.begin(), poll_fds.end(),
		[fd](const pollfd &entry) -> bool { return entry.fd == fd; });

	if ( entry != poll_fds.end() )
		{
		DBG_LOG(DBG_MAINLOOP, "Unregistering fd %d", fd);
		poll_fds.erase(entry);
		fd_map.erase(fd);
		}
	}
