# @TEST-GROUP: leaks
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

function test_case(msg: string, expect: bool)
    {
    print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
    }

event new_connection(c: connection)
	{
	print "new connection";

	local p1: pattern = /foo|bar/; 
	local p2: pattern = /oob/; 
	local p3: pattern = /^oob/; 
	local p4 = /foo/;

	# Type inference tests

	test_case( "type inference", type_name(p4) == "pattern" );

	# Operator tests

	test_case( "equality operator", "foo" == p1 );
	test_case( "equality operator (order of operands)", p1 == "foo" );
	test_case( "inequality operator", "foobar" != p1 );
	test_case( "inequality operator (order of operands)", p1 != "foobar" );
	test_case( "in operator", p1 in "foobar" );
	test_case( "in operator", p2 in "foobar" );
	test_case( "!in operator", p3 !in "foobar" );
	test_case( "& operator", p1 & p2 in "baroob" );
	test_case( "& operator", p2 & p1 in "baroob" );
	test_case( "| operator", p1 | p2 in "lazybarlazy" );
	test_case( "| operator", p3 | p4 in "xoob" );
	}