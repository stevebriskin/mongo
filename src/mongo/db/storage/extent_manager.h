// extent_manager.h

/**
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

#pragma once

#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/db/diskloc.h"

namespace mongo {

    class DataFile;

    /**
     * ExtentManager basics
     *  - one per database
     *  - responsible for managing <db>.# files
     *  - NOT responsible for .ns file
     *  - gives out extents
     *  - responsible for figuring out how to get a new extent
     *  - can use any method it wants to do so
     *  - this structure is NOT stored on disk
     *  - this class is NOT thread safe, locking should be above (for now)
     *
     * implementation:
     *  - ExtentManager holds a list of DataFile
     */
    class ExtentManager {
        MONGO_DISALLOW_COPYING( ExtentManager );

    public:
        ExtentManager( const StringData& dbname, const StringData& path );
        ~ExtentManager();

        /**
         * deletes all state and puts back to original state
         */
        void reset();

        /**
         * opens all current files
         */
        Status init();

        size_t numFiles() const;
        long long fileSize() const;

        DataFile* getFile( int n, int sizeNeeded = 0, bool preallocateOnly = false );

        DataFile* addAFile( int sizeNeeded, bool preallocateNextFile );

        void preallocateAFile() { getFile( numFiles() , 0, true ); }// XXX-ERH

        void flushFiles( bool sync );

        Record* recordFor( const DiskLoc& loc );
        Extent* extentFor( const DiskLoc& loc );

        // get(Next|Prev)Record follows the Record linked list
        // these WILL cross Extent boundaries
        // * @param loc - has to be the DiskLoc for a Record

        DiskLoc getNextRecord( const DiskLoc& loc );

        DiskLoc getPrevRecord( const DiskLoc& loc );

        // does NOT traverse extent boundaries

        DiskLoc getNextRecordInExtent( const DiskLoc& loc );

        DiskLoc getPrevRecordInExtent( const DiskLoc& loc );


    private:

        boost::filesystem::path fileName( int n ) const;


// -----

        std::string _dbname; // i.e. "test"
        std::string _path; // i.e. "/data/db"

        // must be in the dbLock when touching this (and write locked when writing to of course)
        // however during Database object construction we aren't, which is ok as it isn't yet visible
        //   to others and we are in the dbholder lock then.
        std::vector<DataFile*> _files;

    };

}
