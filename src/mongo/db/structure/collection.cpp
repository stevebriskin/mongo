// collection.cpp

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
*
*    As a special exception, the copyright holders give permission to link the
*    code of portions of this program with the OpenSSL library under certain
*    conditions as described in each individual source file and distribute
*    linked combinations including the program with the OpenSSL library. You
*    must comply with the GNU Affero General Public License in all respects for
*    all of the code used other than as permitted herein. If you modify file(s)
*    with this exception, you may extend this exception to your version of the
*    file(s), but you are not obligated to do so. If you do not wish to do so,
*    delete this exception statement from your version. If you delete this
*    exception statement from all source files in the program, then also delete
*    it in the license file.
*/

#include "mongo/db/structure/collection.h"

#include "mongo/db/clientcursor.h"
#include "mongo/db/database.h"
#include "mongo/db/namespace_details.h"
#include "mongo/db/storage/extent.h"
#include "mongo/db/storage/extent_manager.h"
#include "mongo/db/structure/collection_iterator.h"

#include "mongo/db/pdfile.h" // XXX-ERH
#include "mongo/db/index_update.h" // XXX-ERH

namespace mongo {

    Collection::Collection( const StringData& fullNS,
                                    NamespaceDetails* details,
                                    Database* database )
        : _ns( fullNS ), _infoCache( this ) {
        _details = details;
        _database = database;
        _recordStore.init( _details,
                           &database->getExtentManager(),
                           _ns.coll() == "system.indexes" );
        _magic = 1357924;
    }

    Collection::~Collection() {
        verify( ok() );
        _magic = 0;
    }

    CollectionIterator* Collection::getIterator( const DiskLoc& start, bool tailable,
                                                     const CollectionScanParams::Direction& dir) const {
        verify( ok() );
        if ( _details->isCapped() )
            return new CappedIterator( this, start, tailable, dir );
        return new FlatIterator( this, start, dir );
    }

    BSONObj Collection::docFor( const DiskLoc& loc ) {
        Record* rec = getExtentManager()->recordFor( loc );
        return BSONObj::make( rec->accessed() );
    }

    void Collection::deleteDocument( const DiskLoc& loc, bool cappedOK, bool noWarn,
                                         BSONObj* deletedId ) {
        if ( _details->isCapped() && !cappedOK ) {
            log() << "failing remove on a capped ns " << _ns << endl;
            uasserted( 17115,  "cannot remove from a capped collection" ); // XXX 10089
            return;
        }

        if ( deletedId ) {
            BSONObj doc = docFor( loc );
            BSONElement e = doc["_id"];
            if ( e.type() ) {
                *deletedId = e.wrap();
            }
        }

        /* check if any cursors point to us.  if so, advance them. */
        ClientCursor::aboutToDelete(_ns.ns(), _details, loc);

        Record* rec = getExtentManager()->recordFor( loc );

        unindexRecord(_details, rec, loc, noWarn);

        _recordStore.deallocRecord( loc, rec );

        _infoCache.notifyOfWriteOp();
    }


    ExtentManager* Collection::getExtentManager() {
        verify( ok() );
        return &_database->getExtentManager();
    }

    const ExtentManager* Collection::getExtentManager() const {
        verify( ok() );
        return &_database->getExtentManager();
    }

    Extent* Collection::increaseStorageSize( int size, bool enforceQuota ) {

        int quotaMax = 0;
        if ( enforceQuota )
            quotaMax = largestFileNumberInQuota();

        bool fromFreeList = true;
        DiskLoc eloc = getExtentManager()->allocFromFreeList( size, _details->isCapped() );
        if ( eloc.isNull() ) {
            fromFreeList = false;
            eloc = getExtentManager()->createExtent( size, quotaMax );
        }

        verify( !eloc.isNull() );
        verify( eloc.isValid() );

        LOG(1) << "Collection::increaseStorageSize"
               << " ns:" << _ns
               << " desiredSize:" << size
               << " fromFreeList: " << fromFreeList
               << " eloc: " << eloc;

        Extent *e = getExtentManager()->getExtent( eloc, false );
        verify( e );

        DiskLoc emptyLoc = getDur().writing(e)->reuse( _ns.toString(), _details->isCapped() );

        if ( _details->lastExtent().isNull() ) {
            verify( _details->firstExtent().isNull() );
            _details->setFirstExtent( eloc );
            _details->setLastExtent( eloc );
            _details->capExtent() = eloc;
            verify( e->xprev.isNull() );
            verify( e->xnext.isNull() );
        }
        else {
            verify( !_details->firstExtent().isNull() );
            getDur().writingDiskLoc(e->xprev) = _details->lastExtent();
            getDur().writingDiskLoc(_details->lastExtent().ext()->xnext) = eloc;
            _details->setLastExtent( eloc );
        }

        _details->setLastExtentSize( e->length );

        _details->addDeletedRec(emptyLoc.drec(), emptyLoc);

        return e;
    }

    int Collection::largestFileNumberInQuota() const {
        if ( !storageGlobalParams.quota )
            return 0;

        if ( _ns.db() == "local" )
            return 0;

        if ( _ns.isSpecial() )
            return 0;

        return storageGlobalParams.quotaFiles;
    }

    uint64_t Collection::numRecords() const {
        return _details->numRecords();
    }

}
