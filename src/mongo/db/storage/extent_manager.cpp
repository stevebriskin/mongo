// extent_manager.cpp

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

#include "mongo/pch.h"

#include <boost/filesystem/operations.hpp>

#include "mongo/db/client.h"
#include "mongo/db/d_concurrency.h"
#include "mongo/db/storage/data_file.h"
#include "mongo/db/storage/extent_manager.h"

// XXX-erh
#include "mongo/db/pdfile.h"

namespace mongo {

    // XXX-ERH
    extern bool directoryperdb;

    ExtentManager::ExtentManager( const StringData& dbname, const StringData& path )
        : _dbname( dbname.toString() ), _path( path.toString() ) {
    }

    ExtentManager::~ExtentManager() {
        reset();
    }

    void ExtentManager::reset() {
        for ( size_t i = 0; i < _files.size(); i++ ) {
            delete _files[i];
        }
        _files.clear();
    }

    boost::filesystem::path ExtentManager::fileName( int n ) const {
        stringstream ss;
        ss << _dbname << '.' << n;
        boost::filesystem::path fullName( _path );
        if ( directoryperdb )
            fullName /= _dbname;
        fullName /= ss.str();
        return fullName;
    }


    Status ExtentManager::init() {
        verify( _files.size() == 0 );

        for ( int n = 0; n < DiskLoc::MaxFiles; n++ ) {
            boost::filesystem::path fullName = fileName( n );
            if ( !boost::filesystem::exists( fullName ) )
                break;

            string fullNameString = fullName.string();

            auto_ptr<DataFile> df( new DataFile(n) );

            Status s = df->openExisting( fullNameString.c_str() );
            if ( !s.isOK() ) {
                return s;
            }

            if ( df->getHeader()->uninitialized() ) {
                // pre-alloc only, so we're done
                break;
            }

            _files.push_back( df.release() );
        }

        return Status::OK();
    }

    // todo: this is called a lot. streamline the common case
    DataFile* ExtentManager::getFile( int n, int sizeNeeded , bool preallocateOnly) {
        verify(this);
        Lock::assertAtLeastReadLocked( _dbname );

        if ( n < 0 || n >= DiskLoc::MaxFiles ) {
            out() << "getFile(): n=" << n << endl;
            massert( 10295 , "getFile(): bad file number value (corrupt db?): run repair", false);
        }
        DEV {
            if ( n > 100 ) {
                out() << "getFile(): n=" << n << endl;
            }
        }
        DataFile* p = 0;
        if ( !preallocateOnly ) {
            while ( n >= (int) _files.size() ) {
                verify(this);
                if( !Lock::isWriteLocked(_dbname) ) {
                    log() << "error: getFile() called in a read lock, yet file to return is not yet open" << endl;
                    log() << "       getFile(" << n << ") _files.size:" <<_files.size() << ' ' << fileName(n).string() << endl;
                    log() << "       context ns: " << cc().ns() << endl;
                    verify(false);
                }
                _files.push_back(0);
            }
            p = _files[n];
        }
        if ( p == 0 ) {
            Lock::assertWriteLocked( _dbname );
            boost::filesystem::path fullName = fileName( n );
            string fullNameString = fullName.string();
            p = new DataFile(n);
            int minSize = 0;
            if ( n != 0 && _files[ n - 1 ] )
                minSize = _files[ n - 1 ]->getHeader()->fileLength;
            if ( sizeNeeded + DataFileHeader::HeaderSize > minSize )
                minSize = sizeNeeded + DataFileHeader::HeaderSize;
            try {
                p->open( fullNameString.c_str(), minSize, preallocateOnly );
            }
            catch ( AssertionException& ) {
                delete p;
                throw;
            }
            if ( preallocateOnly )
                delete p;
            else
                _files[n] = p;
        }
        return preallocateOnly ? 0 : p;
    }

    DataFile* ExtentManager::addAFile( int sizeNeeded, bool preallocateNextFile ) {
        Lock::assertWriteLocked( _dbname );
        int n = (int) _files.size();
        DataFile *ret = getFile( n, sizeNeeded );
        if ( preallocateNextFile )
            preallocateAFile();
        return ret;
    }

    size_t ExtentManager::numFiles() const {
        DEV Lock::assertAtLeastReadLocked( _dbname );
        return _files.size();
    }

    long long ExtentManager::fileSize() const {
        long long size=0;
        for ( int n = 0; boost::filesystem::exists( fileName(n) ); n++)
            size += boost::filesystem::file_size( fileName(n) );
        return size;
    }

    void ExtentManager::flushFiles( bool sync ) {
        Lock::assertAtLeastReadLocked( _dbname );
        for( vector<DataFile*>::iterator i = _files.begin(); i != _files.end(); i++ ) {
            DataFile *f = *i;
            f->flush(sync);
        }
    }

    Record* ExtentManager::recordFor( const DiskLoc& loc ) {
        return getFile( loc.a() )->recordAt( loc );
    }

    Extent* ExtentManager::extentFor( const DiskLoc& loc ) {
        Record* record = recordFor( loc );
        DiskLoc extentLoc( loc.a(), record->extentOfs() );
        return getFile( loc.a() )->getExtent( extentLoc );
    }

    DiskLoc ExtentManager::getNextRecordInExtent( const DiskLoc& loc ) {
        int nextOffset = recordFor( loc )->nextOfs();

        if ( nextOffset == DiskLoc::NullOfs )
            return DiskLoc();

        fassert( 16967, abs(nextOffset) >= 8 ); // defensive
        return DiskLoc( loc.a(), nextOffset );
    }

    DiskLoc ExtentManager::getNextRecord( const DiskLoc& loc ) {
        DiskLoc next = getNextRecordInExtent( loc );
        if ( !next.isNull() )
            return next;

        // now traverse extents

        Extent *e = extentFor(loc);
        while ( 1 ) {
            if ( e->xnext.isNull() )
                return DiskLoc(); // end of collection
            e = e->xnext.ext();
            if ( !e->firstRecord.isNull() )
                break;
            // entire extent could be empty, keep looking
        }
        return e->firstRecord;
    }

    DiskLoc ExtentManager::getPrevRecordInExtent( const DiskLoc& loc ) {
        int prevOffset = recordFor( loc )->prevOfs();

        if ( prevOffset == DiskLoc::NullOfs )
            return DiskLoc();

        fassert( 16968, abs(prevOffset) >= 8 ); // defensive
        return DiskLoc( loc.a(), prevOffset );
    }

    DiskLoc ExtentManager::getPrevRecord( const DiskLoc& loc ) {
        DiskLoc prev = getPrevRecordInExtent( loc );
        if ( !prev.isNull() )
            return prev;

        // now traverse extents

        Extent *e = extentFor(loc);
        while ( 1 ) {
            if ( e->xprev.isNull() )
                return DiskLoc(); // end of collection
            e = e->xprev.ext();
            if ( !e->firstRecord.isNull() )
                break;
            // entire extent could be empty, keep looking
        }
        return e->firstRecord;
    }


}
