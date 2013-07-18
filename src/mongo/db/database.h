// database.h

/**
*    Copyright (C) 2008 10gen Inc.
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

#pragma once

#include "mongo/db/cc_by_loc.h"
#include "mongo/db/cmdline.h"
#include "mongo/db/namespace_details.h"
#include "mongo/db/record.h"
#include "mongo/db/storage/extent_manager.h"

namespace mongo {

    class Extent;
    class DataFile;

    /**
     * Database represents a database database
     * Each database database has its own set of files -- dbname.ns, dbname.0, dbname.1, ...
     * NOT memory mapped
    */
    class Database {
    public:
        // you probably need to be in dbHolderMutex when constructing this
        Database(const char *nm, /*out*/ bool& newDb, const string& path = dbpath);

        /* you must use this to close - there is essential code in this method that is not in the ~Database destructor.
           thus the destructor is private.  this could be cleaned up one day...
        */
        static void closeDatabase( const string& db, const string& path );

        const string& name() const { return _name; }
        const string& path() const { return _path; }

        void clearTmpCollections();

        /**
         * tries to make sure that this hasn't been deleted
         */
        bool isOk() const { return _magic == 781231; }

        bool isEmpty() { return ! _namespaceIndex.allocated(); }

        /**
         * total file size of Database in bytes
         */
        long long fileSize() const { return _extentManager.fileSize(); }

        int numFiles() const { return _extentManager.numFiles(); }

        /**
         * return file n.  if it doesn't exist, create it
         */
        DataFile* getFile( int n, int sizeNeeded = 0, bool preallocateOnly = false ) {
            _namespaceIndex.init();
            return _extentManager.getFile( n, sizeNeeded, preallocateOnly );
        }

        DataFile* addAFile( int sizeNeeded, bool preallocateNextFile ) {
            return _extentManager.addAFile( sizeNeeded, preallocateNextFile );
        }

        /**
         * makes sure we have an extra file at the end that is empty
         * safe to call this multiple times - the implementation will only preallocate one file
         */
        void preallocateAFile() { _extentManager.preallocateAFile(); }

        DataFile* suitableFile( const char *ns, int sizeNeeded, bool preallocate, bool enforceQuota );

        Extent* allocExtent( const char *ns, int size, bool capped, bool enforceQuota );

        /**
         * @return true if success.  false if bad level or error creating profile ns
         */
        bool setProfilingLevel( int newLevel , string& errmsg );

        void flushFiles( bool sync ) { return _extentManager.flushFiles( sync ); }

        /**
         * @return true if ns is part of the database
         *         ns=foo.bar, db=foo returns true
         */
        bool ownsNS( const string& ns ) const {
            if ( ! startsWith( ns , _name ) )
                return false;
            return ns[_name.size()] == '.';
        }

        const RecordStats& recordStats() const { return _recordStats; }
        RecordStats& recordStats() { return _recordStats; }

        int getProfilingLevel() const { return _profile; }
        const char* getProfilingNS() const { return _profileName.c_str(); }

        CCByLoc& ccByLoc() { return _ccByLoc; }

        const NamespaceIndex& namespaceIndex() const { return _namespaceIndex; }
        NamespaceIndex& namespaceIndex() { return _namespaceIndex; }

        // TODO: do not think this method should exist, so should try and encapsulate better
        ExtentManager& getExtentManager() { return _extentManager; }

        /**
         * @return name of an existing database with same text name but different
         * casing, if one exists.  Otherwise the empty string is returned.  If
         * 'duplicates' is specified, it is filled with all duplicate names.
         */
        static string duplicateUncasedName( bool inholderlockalready, const string &name, const string &path, set< string > *duplicates = 0 );

        static Status validateDBName( const StringData& dbname );

    private:

        ~Database(); // closes files and other cleanup see below.

        /**
         * @throws DatabaseDifferCaseCode if the name is a duplicate based on
         * case insensitive matching.
         */
        void checkDuplicateUncasedNames(bool inholderlockalready) const;

        void openAllFiles();

        /**
         * throws exception if error encounted
         * @return true if the file was opened
         *         false if no errors, but file doesn't exist
         */
        bool openExistingFile( int n );

        const string _name; // "alleyinsider"
        const string _path; // "/data/db"

        NamespaceIndex _namespaceIndex;
        ExtentManager _extentManager;

        const string _profileName; // "alleyinsider.system.profile"

        CCByLoc _ccByLoc; // use by ClientCursor

        RecordStats _recordStats;
        int _profile; // 0=off.

        int _magic; // used for making sure the object is still loaded in memory

    };

} // namespace mongo
