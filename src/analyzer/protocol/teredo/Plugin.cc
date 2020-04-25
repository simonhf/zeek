// See the file  in the main distribution directory for copyright.

#include "Teredo.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Teredo {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("Teredo", ::analyzer::teredo::Teredo_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::Teredo";
		config.description = "Teredo analyzer";
		return config;
		}
} plugin;

}
}
