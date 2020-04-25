// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Hash.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Hash::Hash(RecordVal* args, File* file, HashVal* hv, const char* arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(to_upper(arg_kind).c_str()), args, file), hash(hv), fed(false), kind(arg_kind)
	{
	hash->Init();
	}

Hash::~Hash()
	{
	Unref(hash);
	}

bool Hash::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! hash->IsValid() )
		return false;

	if ( ! fed )
		fed = len > 0;

	hash->Feed(data, len);
	return true;
	}

bool Hash::EndOfFile()
	{
	Finalize();
	return false;
	}

bool Hash::Undelivered(uint64_t offset, uint64_t len)
	{
	return false;
	}

void Hash::Finalize()
	{
	if ( ! hash->IsValid() || ! fed )
		return;

	if ( ! file_hash )
		return;

	mgr.Enqueue(file_hash,
		IntrusivePtr{NewRef{}, GetFile()->GetVal()},
		make_intrusive<StringVal>(kind),
		hash->Get()
	);
	}
