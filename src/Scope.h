// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <string>
#include <map>

#include "Obj.h"
#include "BroList.h"
#include "IntrusivePtr.h"
#include "TraverseTypes.h"

template <class T> class IntrusivePtr;
class ID;
class BroType;
class ListVal;

class Scope : public BroObj {
public:
	explicit Scope(IntrusivePtr<ID> id, attr_list* al);
	~Scope() override;

	template<typename N>
	ID* Lookup(N&& name) const
		{
		const auto& entry = local.find(std::forward<N>(name));

		if ( entry != local.end() )
			return entry->second.get();

		return nullptr;
		}

	template<typename N, typename I>
	void Insert(N&& name, I&& id) { local[std::forward<N>(name)] = std::forward<I>(id); }

	template<typename N>
	IntrusivePtr<ID> Remove(N&& name)
		{
		const auto& entry = local.find(std::forward<N>(name));

		if ( entry != local.end() )
			{
			auto id = std::move(entry->second);
			local.erase(entry);
			return id;
			}

		return nullptr;
		}

	ID* ScopeID() const		{ return scope_id.get(); }
	attr_list* Attrs() const	{ return attrs; }
	BroType* ReturnType() const	{ return return_type.get(); }

	size_t Length() const		{ return local.size(); }
	const auto& Vars()	{ return local; }

	ID* GenerateTemporary(const char* name);

	// Returns the list of variables needing initialization, and
	// removes it from this Scope.
	id_list* GetInits();

	// Adds a variable to the list.
	void AddInit(IntrusivePtr<ID> id)		{ inits->push_back(id.release()); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	IntrusivePtr<ID> scope_id;
	attr_list* attrs;
	IntrusivePtr<BroType> return_type;
	std::map<std::string, IntrusivePtr<ID>> local;
	id_list* inits;
};


extern bool in_debug;

// If no_global is true, don't search in the default "global" namespace.
extern IntrusivePtr<ID> lookup_ID(const char* name, const char* module,
                                  bool no_global = false,
                                  bool same_module_only = false,
                                  bool check_export = true);

extern IntrusivePtr<ID> install_ID(const char* name, const char* module_name,
                                   bool is_global, bool is_export);

extern void push_scope(IntrusivePtr<ID> id, attr_list* attrs);
extern void push_existing_scope(Scope* scope);

// Returns the one popped off.
extern IntrusivePtr<Scope> pop_scope();
extern Scope* current_scope();
extern Scope* global_scope();

// Current module (identified by its name).
extern std::string current_module;
