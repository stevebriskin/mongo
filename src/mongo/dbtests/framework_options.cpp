/*
 *    Copyright (C) 2013 10gen Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mongo/dbtests/framework_options.h"

#include <boost/filesystem/operations.hpp>

#include "mongo/base/status.h"
#include "mongo/bson/util/builder.h"
#include "mongo/db/query/new_find.h"
#include "mongo/db/repl/replication_server_status.h"  // replSettings
#include "mongo/db/storage_options.h"
#include "mongo/dbtests/dbtests.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/options_parser/startup_option_init.h"
#include "mongo/util/options_parser/startup_options.h"
#include "mongo/util/password.h"

namespace mongo {

    FrameworkGlobalParams frameworkGlobalParams;

    Status addTestFrameworkOptions(moe::OptionSection* options) {

        typedef moe::OptionDescription OD;
        typedef moe::PositionalOptionDescription POD;

        Status ret = options->addOption(OD("help", "help,h", moe::Switch,
                    "show this usage information", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("dbpath", "dbpath", moe::String,
                    "db data path for this test run. NOTE: the contents of this directory will "
                    "be overwritten if it already exists", true, moe::Value(default_test_dbpath)));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("debug", "debug", moe::Switch,
                    "run tests with verbose output", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("list", "list,l", moe::Switch, "list available test suites",
                    true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("bigfiles", "bigfiles", moe::Switch,
                    "use big datafiles instead of smallfiles which is the default", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("filter", "filter,f", moe::String,
                    "string substring filter on test name" , true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("verbose", "verbose,v", moe::Switch, "verbose", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("useNewQueryFramework", "useNewQueryFramework", moe::Switch,
                    "use the new query framework", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("dur", "dur", moe::Switch,
                    "enable journaling (currently the default)", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("nodur", "nodur", moe::Switch, "disable journaling", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("seed", "seed", moe::UnsignedLongLong, "random number seed",
                    true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("runs", "runs", moe::Int,
                    "number of times to run each test", true));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("perfHist", "perfHist", moe::Unsigned,
                    "number of back runs of perf stats to display", true));
        if (!ret.isOK()) {
            return ret;
        }

        ret = options->addOption(OD("suites", "suites", moe::StringVector, "test suites to run",
                    false));
        if (!ret.isOK()) {
            return ret;
        }
        ret = options->addOption(OD("nopreallocj", "nopreallocj", moe::Switch,
                    "disable journal prealloc", false));
        if (!ret.isOK()) {
            return ret;
        }

        ret = options->addPositionalOption(POD("suites", moe::String, -1));
        if (!ret.isOK()) {
            return ret;
        }

        return Status::OK();
    }

    std::string getTestFrameworkHelp(const StringData& name, const moe::OptionSection& options) {
        StringBuilder sb;
        sb << "usage: " << name << " [options] [suite]...\n"
            << options.helpString() << "suite: run the specified test suite(s) only\n";
        return sb.str();
    }

    Status handlePreValidationTestFrameworkOptions(const moe::Environment& params,
                                                   const std::vector<std::string>& args) {
        if (params.count("help")) {
            std::cout << getTestFrameworkHelp(args[0], moe::startupOptions) << std::endl;
            ::_exit(EXIT_SUCCESS);
        }

        if (params.count("list")) {
            std::vector<std::string> suiteNames = mongo::unittest::getAllSuiteNames();
            for ( std::vector<std::string>::const_iterator i = suiteNames.begin();
                    i != suiteNames.end(); ++i ) {

                std::cout << *i << std::endl;
            }
            ::_exit(EXIT_SUCCESS);
        }

        return Status::OK();
    }

    Status storeTestFrameworkOptions(const moe::Environment& params,
                                     const std::vector<std::string>& args) {

        if (params.count("useNewQueryFramework")) {
            mongo::enableNewQueryFramework();
        }

        if (params.count("dbpath")) {
            frameworkGlobalParams.dbpathSpec = params["dbpath"].as<string>();
        }

        if (params.count("seed")) {
            frameworkGlobalParams.seed = params["seed"].as<unsigned long long>();
        }

        if (params.count("runs")) {
            frameworkGlobalParams.runsPerTest = params["runs"].as<int>();
        }

        if (params.count("perfHist")) {
            frameworkGlobalParams.perfHist = params["perfHist"].as<unsigned>();
        }

        bool nodur = false;
        if( params.count("nodur") ) {
            nodur = true;
            storageGlobalParams.dur = false;
        }
        if( params.count("dur") || storageGlobalParams.dur ) {
            storageGlobalParams.dur = true;
        }

        if( params.count("nopreallocj") ) {
            storageGlobalParams.preallocj = false;
        }

        if (params.count("debug") || params.count("verbose") ) {
            logger::globalLogDomain()->setMinimumLoggedSeverity(logger::LogSeverity::Debug(1));
        }

        boost::filesystem::path p(frameworkGlobalParams.dbpathSpec);

        /* remove the contents of the test directory if it exists. */
        try {
            if (boost::filesystem::exists(p)) {
                if (!boost::filesystem::is_directory(p)) {
                    std::cerr << "ERROR: path \"" << p.string() << "\" is not a directory"
                                << std::endl;
                    std::cerr << getTestFrameworkHelp(args[0], moe::startupOptions) << std::endl;
                    ::_exit(EXIT_BADOPTIONS);
                }
                boost::filesystem::directory_iterator end_iter;
                for (boost::filesystem::directory_iterator dir_iter(p);
                        dir_iter != end_iter; ++dir_iter) {
                    boost::filesystem::remove_all(*dir_iter);
                }
            }
            else {
                boost::filesystem::create_directory(p);
            }
        }
        catch (const boost::filesystem::filesystem_error& e) {
            std::cerr << "boost::filesystem threw exception: " << e.what() << std::endl;
            ::_exit(EXIT_BADOPTIONS);
        }

        string dbpathString = p.string();
        storageGlobalParams.dbpath = dbpathString.c_str();

        storageGlobalParams.prealloc = false;

        // dbtest defaults to smallfiles
        storageGlobalParams.smallfiles = true;
        if( params.count("bigfiles") ) {
            storageGlobalParams.dur = true;
        }

        replSettings.oplogSize = 10 * 1024 * 1024;

        DEV log() << "_DEBUG build" << endl;
        if( sizeof(void*)==4 )
            log() << "32bit" << endl;
        log() << "random seed: " << frameworkGlobalParams.seed << endl;

        if( time(0) % 3 == 0 && !nodur ) {
            if (!storageGlobalParams.dur) {
                storageGlobalParams.dur = true;
                log() << "****************" << endl;
                log() << "running with journaling enabled to test that. dbtests will do this "
                      << "occasionally even if --dur is not specified." << endl;
                log() << "****************" << endl;
            }
        }

        if (params.count("suites")) {
            frameworkGlobalParams.suites = params["suites"].as< vector<string> >();
        }

        frameworkGlobalParams.filter = "";
        if ( params.count( "filter" ) ) {
            frameworkGlobalParams.filter = params["filter"].as<string>();
        }

        if (debug && storageGlobalParams.dur) {
            log() << "_DEBUG: automatically enabling storageGlobalParams.durOptions=8 "
                  << "(DurParanoid)" << endl;
            // this was commented out.  why too slow or something?
            storageGlobalParams.durOptions |= 8;
        }

        return Status::OK();
    }

    MONGO_GENERAL_STARTUP_OPTIONS_REGISTER(FrameworkOptions)(InitializerContext* context) {
        return addTestFrameworkOptions(&moe::startupOptions);
    }

    MONGO_STARTUP_OPTIONS_VALIDATE(FrameworkOptions)(InitializerContext* context) {
        Status ret = handlePreValidationTestFrameworkOptions(moe::startupOptionsParsed,
                                                             context->args());
        if (!ret.isOK()) {
            return ret;
        }
        ret = moe::startupOptionsParsed.validate();
        if (!ret.isOK()) {
            return ret;
        }
        return Status::OK();
    }

    MONGO_STARTUP_OPTIONS_STORE(FrameworkOptions)(InitializerContext* context) {
        return storeTestFrameworkOptions(moe::startupOptionsParsed, context->args());
    }
}
