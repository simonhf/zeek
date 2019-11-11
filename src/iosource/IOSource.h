// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

extern "C" {
#include <pcap.h>
}

#include <string>
#include "Timer.h"

namespace iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main
 * loop.
 */
class IOSource {
public:
	/**
	 * Constructor.
	 */
	IOSource()	{ idle = false; closed = false; }

	/**
	 * Destructor.
	 */
	virtual ~IOSource()	{}

	/**
	 * Returns true if source has nothing ready to process.
	 */
	bool IsIdle() const	{ return idle; }

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const	{ return ! closed; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void Init()	{ }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done()	{ }

	/**
	 * Return the next timeout value for this source. This should be
	 * overridden by source classes where they have a timeout value
	 * that can wake up the poll.
	 *
	 * @return A value for the next time that the source thinks the
	 * poll should time out in seconds from the current time. Return
	 * -1 if this should should not be considered.
	 */
	virtual double GetNextTimeout() { return -1; }

	/**
	 * Processes and consumes next data item.
	 *
	 * This method will be called only when either IsIdle() returns
	 * false, or select() on one of the fds returned by GetFDs()
	 * indicates that there's data to process.
	 *
	 * Must be overridden by derived classes.
	 */
	virtual void Process() = 0;

	/**
	 * Returns the tag of the timer manafger associated with the last
	 * procesees data item.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The tag, or null for the global timer manager.
	 *
	 */
	virtual TimerMgr::Tag* GetCurrentTag()	{ return 0; }

	/**
	 * Returns a descriptive tag representing the source for debugging.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;

protected:
	/*
	 * Callback for derived classes to call when they have gone dry
	 * temporarily.
	 *
	 * @param is_idle True if the source is idle currently.
	 */
	void SetIdle(bool is_idle)	{ idle = is_idle; }

	/*
	 * Callback for derived class to call when they have shutdown.
	 *
	 * @param is_closed True if the source is now closed.
	 */
	void SetClosed(bool is_closed)	{ closed = is_closed; }

private:
	bool idle;
	bool closed;
};

}
