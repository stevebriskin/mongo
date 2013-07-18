//@file update.cpp

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

#include "mongo/pch.h"

#include "mongo/db/ops/update.h"

#include <cstring>  // for memcpy

#include "mongo/bson/mutable/damage_vector.h"
#include "mongo/bson/mutable/document.h"
#include "mongo/client/dbclientinterface.h"
#include "mongo/db/clientcursor.h"
#include "mongo/db/index_set.h"
#include "mongo/db/namespace_details.h"
#include "mongo/db/ops/update_driver.h"
#include "mongo/db/ops/update_internal.h"
#include "mongo/db/pagefault.h"
#include "mongo/db/pdfile.h"
#include "mongo/db/query_optimizer.h"
#include "mongo/db/query_runner.h"
#include "mongo/db/queryutil.h"
#include "mongo/db/record.h"
#include "mongo/db/repl/oplog.h"
#include "mongo/db/server_parameters.h"
#include "mongo/platform/unordered_set.h"

//#define DEBUGUPDATE(x) cout << x << endl;
#define DEBUGUPDATE(x)

namespace mongo {

    MONGO_EXPORT_SERVER_PARAMETER( newUpdateFrameworkEnabled, bool, false );

    bool isNewUpdateFrameworkEnabled() {
        return newUpdateFrameworkEnabled;
    }

    void checkNoMods( BSONObj o ) {
        BSONObjIterator i( o );
        while( i.moreWithEOO() ) {
            BSONElement e = i.next();
            if ( e.eoo() )
                break;
            uassert( 10154 ,  "Modifiers and non-modifiers cannot be mixed", e.fieldName()[ 0 ] != '$' );
        }
    }

    static void checkTooLarge(const BSONObj& newObj) {
        uassert( 12522 , "$ operator made object too large" , newObj.objsize() <= BSONObjMaxUserSize );
    }

    /* note: this is only (as-is) called for

             - not multi
             - not mods is indexed
             - not upsert
    */
    static UpdateResult _updateById(bool isOperatorUpdate,
                                    int idIdxNo,
                                    ModSet* mods,
                                    NamespaceDetails* d,
                                    NamespaceDetailsTransient *nsdt,
                                    bool su,
                                    const char* ns,
                                    const BSONObj& updateobj,
                                    BSONObj patternOrig,
                                    bool logop,
                                    OpDebug& debug,
                                    bool fromMigrate = false) {

        DiskLoc loc;
        {
            IndexDetails& i = d->idx(idIdxNo);
            BSONObj key = i.getKeyFromQuery( patternOrig );
            loc = QueryRunner::fastFindSingle(i, key);
            if( loc.isNull() ) {
                // no upsert support in _updateById yet, so we are done.
                return UpdateResult( 0 , 0 , 0 , BSONObj() );
            }
        }
        Record* r = loc.rec();

        if ( cc().allowedToThrowPageFaultException() && ! r->likelyInPhysicalMemory() ) {
            throw PageFaultException( r );
        }

        /* look for $inc etc.  note as listed here, all fields to inc must be this type, you can't set some
           regular ones at the moment. */
        BSONObj newObj;
        if ( isOperatorUpdate ) {
            const BSONObj& onDisk = loc.obj();
            auto_ptr<ModSetState> mss = mods->prepare( onDisk, false /* not an insertion */ );

            if( mss->canApplyInPlace() ) {
                mss->applyModsInPlace(true);
                debug.fastmod = true;
                DEBUGUPDATE( "\t\t\t updateById doing in place update" );

                newObj = onDisk;
            }
            else {
                newObj = mss->createNewFromMods();
                checkTooLarge(newObj);
                verify(nsdt);
                theDataFileMgr.updateRecord(ns, d, nsdt, r, loc , newObj.objdata(), newObj.objsize(), debug);
            }

            if ( logop ) {
                DEV verify( mods->size() );
                BSONObj pattern = patternOrig;
                BSONObj logObj = mss->getOpLogRewrite();
                DEBUGUPDATE( "\t rewrite update: " << logObj );

                // It is possible that the entire mod set was a no-op over this document.  We
                // would have an empty log record in that case. If we call logOp, with an empty
                // record, that would be replicated as "clear this record", which is not what
                // we want. Therefore, to get a no-op in the replica, we simply don't log.
                if ( logObj.nFields() ) {
                    logOp("u", ns, logObj, &pattern, 0, fromMigrate, &newObj );
                }
            }
            return UpdateResult( 1 , 1 , 1 , BSONObj() );

        } // end $operator update

        // regular update
        BSONElementManipulator::lookForTimestamps( updateobj );
        checkNoMods( updateobj );
        verify(nsdt);
        theDataFileMgr.updateRecord(ns, d, nsdt, r, loc , updateobj.objdata(), updateobj.objsize(), debug );
        if ( logop ) {
            logOp("u", ns, updateobj, &patternOrig, 0, fromMigrate, &updateobj );
        }
        return UpdateResult( 1 , 0 , 1 , BSONObj() );
    }

    UpdateResult _updateObjects( bool su,
                                 const char* ns,
                                 const BSONObj& updateobj,
                                 const BSONObj& patternOrig,
                                 bool upsert,
                                 bool multi,
                                 bool logop ,
                                 OpDebug& debug,
                                 RemoveSaver* rs,
                                 bool fromMigrate,
                                 const QueryPlanSelectionPolicy& planPolicy,
                                 bool forReplication ) {

        DEBUGUPDATE( "update: " << ns
                     << " update: " << updateobj
                     << " query: " << patternOrig
                     << " upsert: " << upsert << " multi: " << multi );

        Client& client = cc();

        debug.updateobj = updateobj;

        // The idea with these here it to make them loop invariant for
        // multi updates, and thus be a bit faster for that case.  The
        // pointers may be left invalid on a failed or terminal yield
        // recovery.
        NamespaceDetails* d = nsdetails(ns); // can be null if an upsert...
        NamespaceDetailsTransient* nsdt = &NamespaceDetailsTransient::get(ns);

        auto_ptr<ModSet> mods;
        bool isOperatorUpdate = updateobj.firstElementFieldName()[0] == '$';
        int modsIsIndexed = false; // really the # of indexes
        if ( isOperatorUpdate ) {
            mods.reset( new ModSet(updateobj, nsdt->indexKeys(), forReplication) );
            modsIsIndexed = mods->maxNumIndexUpdated();
        }

        if( planPolicy.permitOptimalIdPlan() && !multi && isSimpleIdQuery(patternOrig) && d &&
           !modsIsIndexed ) {
            int idxNo = d->findIdIndex();
            if( idxNo >= 0 ) {
                debug.idhack = true;

                UpdateResult result = _updateById( isOperatorUpdate,
                                                   idxNo,
                                                   mods.get(),
                                                   d,
                                                   nsdt,
                                                   su,
                                                   ns,
                                                   updateobj,
                                                   patternOrig,
                                                   logop,
                                                   debug,
                                                   fromMigrate);
                if ( result.existing || ! upsert ) {
                    return result;
                }
                else if ( upsert && ! isOperatorUpdate ) {
                    // this handles repl inserts
                    checkNoMods( updateobj );
                    debug.upsert = true;
                    BSONObj no = updateobj;
                    theDataFileMgr.insertWithObjMod(ns, no, false, su);
                    if ( logop )
                        logOp( "i", ns, no, 0, 0, fromMigrate, &no );

                    return UpdateResult( 0 , 0 , 1 , no );
                }
            }
        }

        int numModded = 0;
        debug.nscanned = 0;
        shared_ptr<Cursor> c = getOptimizedCursor( ns, patternOrig, BSONObj(), planPolicy );
        d = nsdetails(ns);
        nsdt = &NamespaceDetailsTransient::get(ns);
        bool autoDedup = c->autoDedup();

        if( c->ok() ) {
            set<DiskLoc> seenObjects;
            MatchDetails details;
            auto_ptr<ClientCursor> cc;
            do {

                if ( cc.get() == 0 &&
                     client.allowedToThrowPageFaultException() &&
                     ! c->currLoc().isNull() &&
                     ! c->currLoc().rec()->likelyInPhysicalMemory() ) {
                    throw PageFaultException( c->currLoc().rec() );
                }

                bool atomic = c->matcher() && c->matcher()->docMatcher().atomic();

                if ( ! atomic && debug.nscanned > 0 ) {
                    // we need to use a ClientCursor to yield
                    if ( cc.get() == 0 ) {
                        shared_ptr< Cursor > cPtr = c;
                        cc.reset( new ClientCursor( QueryOption_NoCursorTimeout , cPtr , ns ) );
                    }

                    bool didYield;
                    if ( ! cc->yieldSometimes( ClientCursor::WillNeed, &didYield ) ) {
                        cc.release();
                        break;
                    }
                    if ( !c->ok() ) {
                        break;
                    }

                    if ( didYield ) {
                        d = nsdetails(ns);
                        if ( ! d )
                            break;
                        nsdt = &NamespaceDetailsTransient::get(ns);
                        if ( mods.get() ) {
                            mods->setIndexedStatus( nsdt->indexKeys() );
                            modsIsIndexed = mods->maxNumIndexUpdated();
                        }

                    }

                } // end yielding block

                debug.nscanned++;

                if ( mods.get() && mods->hasDynamicArray() ) {
                    details.requestElemMatchKey();
                }

                if ( !c->currentMatches( &details ) ) {
                    c->advance();
                    continue;
                }

                Record* r = c->_current();
                DiskLoc loc = c->currLoc();

                if ( c->getsetdup( loc ) && autoDedup ) {
                    c->advance();
                    continue;
                }

                BSONObj js = BSONObj::make(r);

                BSONObj pattern = patternOrig;

                if ( logop ) {
                    BSONObjBuilder idPattern;
                    BSONElement id;
                    // NOTE: If the matching object lacks an id, we'll log
                    // with the original pattern.  This isn't replay-safe.
                    // It might make sense to suppress the log instead
                    // if there's no id.
                    if ( js.getObjectID( id ) ) {
                        idPattern.append( id );
                        pattern = idPattern.obj();
                    }
                    else {
                        uassert( 10157 ,  "multi-update requires all modified objects to have an _id" , ! multi );
                    }
                }

                /* look for $inc etc.  note as listed here, all fields to inc must be this type, you can't set some
                    regular ones at the moment. */
                if ( isOperatorUpdate ) {

                    if ( multi ) {
                        // go to next record in case this one moves
                        c->advance();

                        // Update operations are deduped for cursors that implement their own
                        // deduplication.  In particular, some geo cursors are excluded.
                        if ( autoDedup ) {

                            if ( seenObjects.count( loc ) ) {
                                continue;
                            }

                            // SERVER-5198 Advance past the document to be modified, provided
                            // deduplication is enabled, but see SERVER-5725.
                            while( c->ok() && loc == c->currLoc() ) {
                                c->advance();
                            }
                        }
                    }

                    const BSONObj& onDisk = loc.obj();

                    ModSet* useMods = mods.get();

                    auto_ptr<ModSet> mymodset;
                    if ( details.hasElemMatchKey() && mods->hasDynamicArray() ) {
                        useMods = mods->fixDynamicArray( details.elemMatchKey() );
                        mymodset.reset( useMods );
                    }

                    auto_ptr<ModSetState> mss = useMods->prepare( onDisk,
                                                                  false /* not an insertion */ );

                    bool willAdvanceCursor = multi && c->ok() && ( modsIsIndexed || ! mss->canApplyInPlace() );

                    if ( willAdvanceCursor ) {
                        if ( cc.get() ) {
                            cc->setDoingDeletes( true );
                        }
                        c->prepareToTouchEarlierIterate();
                    }

                    // If we've made it this far, "ns" must contain a valid collection name, and so
                    // is of the form "db.collection".  Therefore, the following expression must
                    // always be valid.  "system.users" updates must never be done in place, in
                    // order to ensure that they are validated inside DataFileMgr::updateRecord(.).
                    bool isSystemUsersMod = nsToCollectionSubstring(ns) == "system.users";

                    BSONObj newObj;
                    if ( !mss->isUpdateIndexed() && mss->canApplyInPlace() && !isSystemUsersMod ) {
                        mss->applyModsInPlace( true );// const_cast<BSONObj&>(onDisk) );

                        DEBUGUPDATE( "\t\t\t doing in place update" );
                        if ( !multi )
                            debug.fastmod = true;

                        if ( modsIsIndexed ) {
                            seenObjects.insert( loc );
                        }
                        newObj = loc.obj();
                        d->paddingFits();
                    }
                    else {
                        newObj = mss->createNewFromMods();
                        checkTooLarge(newObj);
                        DiskLoc newLoc = theDataFileMgr.updateRecord(ns,
                                                                     d,
                                                                     nsdt,
                                                                     r,
                                                                     loc,
                                                                     newObj.objdata(),
                                                                     newObj.objsize(),
                                                                     debug);

                        if ( newLoc != loc || modsIsIndexed ){
                            // log() << "Moved obj " << newLoc.obj()["_id"] << " from " << loc << " to " << newLoc << endl;
                            // object moved, need to make sure we don' get again
                            seenObjects.insert( newLoc );
                        }

                    }

                    if ( logop ) {
                        DEV verify( mods->size() );
                        BSONObj logObj = mss->getOpLogRewrite();
                        DEBUGUPDATE( "\t rewrite update: " << logObj );

                        // It is possible that the entire mod set was a no-op over this
                        // document.  We would have an empty log record in that case. If we
                        // call logOp, with an empty record, that would be replicated as "clear
                        // this record", which is not what we want. Therefore, to get a no-op
                        // in the replica, we simply don't log.
                        if ( logObj.nFields() ) {
                            logOp("u", ns, logObj , &pattern, 0, fromMigrate, &newObj );
                        }
                    }
                    numModded++;
                    if ( ! multi )
                        return UpdateResult( 1 , 1 , numModded , BSONObj() );
                    if ( willAdvanceCursor )
                        c->recoverFromTouchingEarlierIterate();

                    getDur().commitIfNeeded();

                    continue;
                }

                uassert( 10158 ,  "multi update only works with $ operators" , ! multi );

                BSONElementManipulator::lookForTimestamps( updateobj );
                checkNoMods( updateobj );
                theDataFileMgr.updateRecord(ns, d, nsdt, r, loc , updateobj.objdata(), updateobj.objsize(), debug, su);
                if ( logop ) {
                    DEV wassert( !su ); // super used doesn't get logged, this would be bad.
                    logOp("u", ns, updateobj, &pattern, 0, fromMigrate, &updateobj );
                }
                return UpdateResult( 1 , 0 , 1 , BSONObj() );
            } while ( c->ok() );
        } // endif

        if ( numModded )
            return UpdateResult( 1 , 1 , numModded , BSONObj() );

        if ( upsert ) {
            if ( updateobj.firstElementFieldName()[0] == '$' ) {
                // upsert of an $operation. build a default object
                BSONObj newObj = mods->createNewFromQuery( patternOrig );
                checkNoMods( newObj );
                debug.fastmodinsert = true;
                theDataFileMgr.insertWithObjMod(ns, newObj, false, su);
                if ( logop )
                    logOp( "i", ns, newObj, 0, 0, fromMigrate, &newObj );

                return UpdateResult( 0 , 1 , 1 , newObj );
            }
            uassert( 10159 ,  "multi update only works with $ operators" , ! multi );
            checkNoMods( updateobj );
            debug.upsert = true;
            BSONObj no = updateobj;
            theDataFileMgr.insertWithObjMod(ns, no, false, su);
            if ( logop )
                logOp( "i", ns, no, 0, 0, fromMigrate, &no );
            return UpdateResult( 0 , 0 , 1 , no );
        }

        return UpdateResult( 0 , isOperatorUpdate , 0 , BSONObj() );
    }

    void validateUpdate( const char* ns , const BSONObj& updateobj, const BSONObj& patternOrig ) {
        uassert( 10155 , "cannot update reserved $ collection", strchr(ns, '$') == 0 );
        if ( strstr(ns, ".system.") ) {
            /* dm: it's very important that system.indexes is never updated as IndexDetails
               has pointers into it */
            uassert( 10156,
                     str::stream() << "cannot update system collection: "
                                   << ns << " q: " << patternOrig << " u: " << updateobj,
                     legalClientSystemNS( ns , true ) );
        }
    }

    UpdateResult _updateObjectsNEW( bool su,
                                    const char* ns,
                                    const BSONObj& updateobj,
                                    const BSONObj& patternOrig,
                                    bool upsert,
                                    bool multi,
                                    bool logop ,
                                    OpDebug& debug,
                                    RemoveSaver* rs,
                                    bool fromMigrate,
                                    const QueryPlanSelectionPolicy& planPolicy,
                                    bool forReplication ) {

        // TODO
        // + Separate UpdateParser from UpdateRunner (the latter should be "stage-y")
        //   + All the yield and deduplicate logic would move to the query stage
        //     portion of it
        //
        // + Replication related
        //   + fast path for update for query by _id
        //   + support for relaxing viable path constraint in replication
        //
        // + Field Management
        //   + Force all upsert to contain _id
        //   + Prevent changes to immutable fields (_id, and those mentioned by sharding)
        //
        // + Yiedling related
        //   + $atomic support (or better, support proper yielding if not)
        //   + page fault support

        debug.updateobj = updateobj;

        NamespaceDetails* d = nsdetails( ns );
        NamespaceDetailsTransient* nsdt = &NamespaceDetailsTransient::get( ns );

        UpdateDriver::Options opts;
        opts.multi = multi;
        opts.upsert = upsert;
        opts.logOp = logop;
        UpdateDriver driver( opts );
        Status status = driver.parse( nsdt->indexKeys(), updateobj );
        if ( !status.isOK() ) {
            uasserted( 16840, status.reason() );
        }

        shared_ptr<Cursor> cursor = getOptimizedCursor( ns, patternOrig, BSONObj(), planPolicy );

        // The 'cursor' the optimizer gave us may contain query plans that generate duplicate
        // diskloc's. We set up here the mechanims that will prevent us from processing those
        // twice if we see them. We also set up a 'ClientCursor' so that we can support
        // yielding.
        const bool dedupHere = cursor->autoDedup();
        shared_ptr<Cursor> cPtr = cursor;
        auto_ptr<ClientCursor> clientCursor( new ClientCursor( QueryOption_NoCursorTimeout,
                                                               cPtr,
                                                               ns ) );

        //
        // We'll start assuming we have one or more documents for this update. (Othwerwise,
        // we'll fallback to upserting.)
        //

        // We record that this will not be an upsert, in case a mod doesn't want to be applied
        // when in strict update mode.
        driver.setContext( ModifierInterface::ExecInfo::UPDATE_CONTEXT );

        // Let's fetch each of them and pipe them through the update expression, making sure to
        // keep track of the necessary stats. Recall that we'll be pulling documents out of
        // cursors and some of them do not deduplicate the entries they generate. We have
        // deduping logic in here, too -- for now.
        unordered_set<DiskLoc, DiskLoc::Hasher> seenLocs;
        int numUpdated = 0;
        debug.nscanned = 0;
        while ( cursor->ok() ) {

            // Let's fetch the next candidate object for this update.
            Record* r = cursor->_current();
            DiskLoc loc = cursor->currLoc();
            const BSONObj oldObj = loc.obj();

            // We count how many documents we scanned even though we may skip those that are
            // deemed duplicated. The final 'numUpdated' and 'nscanned' numbers may differ for
            // that reason.
            debug.nscanned++;

            // Skips this document if it:
            // a) doesn't match the query portion of the update
            // b) was deemed duplicate by the underlying cursor machinery
            //
            // Now, if we are going to update the document,
            // c) we don't want to do so while the cursor is at it, as that may invalidate
            // the cursor. So, we advance to next document, before issuing the update.
            MatchDetails matchDetails;
            matchDetails.requestElemMatchKey();
            if ( !cursor->currentMatches( &matchDetails ) ) {
                // a)
                cursor->advance();
                continue;
            }
            else if ( cursor->getsetdup( loc ) && dedupHere ) {
                // b)
                cursor->advance();
                continue;
            }
            else if (driver.dollarModMode() && multi) {
                // c)
                cursor->advance();
                if ( dedupHere ) {
                    if ( seenLocs.count( loc ) ) {
                        continue;
                    }
                }

                // There are certain kind of cursors that hold multiple pointers to data
                // underneath. $or cursors is one example. In a $or cursor, it may be the case
                // that when we did the last advance(), we finished consuming documents from
                // one of $or child and started consuming the next one. In that case, it is
                // possible that the last document of the previous child is the same as the
                // first document of the next (see SERVER-5198 and jstests/orp.js).
                //
                // So we advance the cursor here until we see a new diskloc.
                //
                // Note that we won't be yielding, and we may not do so for a while if we find
                // a particularly duplicated sequence of loc's. That is highly unlikely,
                // though.  (See SERVER-5725, if curious, but "stage" based $or will make that
                // ticket moot).
                while( cursor->ok() && loc == cursor->currLoc() ) {
                    cursor->advance();
                }
            }

            // For some (unfortunate) historical reasons, not all cursors would be valid after
            // a write simply because we advanced them to a document not affected by the write.
            // To protect in those cases, not only we engaged in the advance() logic above, but
            // we also tell the cursor we're about to write a document that we've just seen.
            // prepareToTouchEarlierIterate() requires calling later
            // recoverFromTouchingEarlierIterate(), so we make a note here to do so.
            bool touchPreviousDoc = multi && cursor->ok();
            if ( touchPreviousDoc  ) {
                clientCursor->setDoingDeletes( true );
                cursor->prepareToTouchEarlierIterate();
            }

            // Ask the driver to apply the mods. It may be that the driver can apply those "in
            // place", that is, some values of the old document just get adjusted without any
            // change to the binary layout on the bson layer. It may be that a whole new
            // document is needed to accomodate the new bson layout of the resulting document.
            mutablebson::Document doc( oldObj, mutablebson::Document::kInPlaceEnabled );
            BSONObj logObj;
            StringData matchedField = matchDetails.hasElemMatchKey() ?
                                                    matchDetails.elemMatchKey():
                                                    StringData();
            status = driver.update( matchedField, &doc, &logObj );
            if ( !status.isOK() ) {
                uasserted( 16837, status.reason() );
            }

            // If the driver applied the mods in place, we can ask the mutable for what
            // changed. We call those changes "damages". :) We use the damages to inform the
            // journal what was changed, and then apply them to the original document
            // ourselves. If, however, the driver applied the mods out of place, we ask it to
            // generate a new, modified document for us. In that case, the file manager will
            // take care of the journaling details for us.
            //
            // This code flow is admittedly odd. But, right now, journaling is baked in the file
            // manager. And if we aren't using the file manager, we have to do jounaling
            // ourselves.
            BSONObj newObj;
            const char* source = NULL;
            mutablebson::DamageVector damages;
            bool inPlace = doc.getInPlaceUpdates(&damages, &source);
            if ( inPlace && !driver.modsAffectIndices() ) {

                // All updates were in place. Apply them via durability and writing pointer.
                mutablebson::DamageVector::const_iterator where = damages.begin();
                const mutablebson::DamageVector::const_iterator end = damages.end();
                for( ; where != end; ++where ) {
                    const char* sourcePtr = source + where->sourceOffset;
                    void* targetPtr = getDur().writingPtr(
                        const_cast<char*>(oldObj.objdata()) + where->targetOffset,
                        where->size);
                    std::memcpy(targetPtr, sourcePtr, where->size);
                }
                newObj = oldObj;
                debug.fastmod = true;
            }
            else {

                // The updates were not in place. Apply them through the file manager.
                newObj = doc.getObject();
                DiskLoc newLoc = theDataFileMgr.updateRecord(ns,
                                                             d,
                                                             nsdt,
                                                             r,
                                                             loc,
                                                             newObj.objdata(),
                                                             newObj.objsize(),
                                                             debug);

                // If we've moved this object to a new location, make sure we don't apply
                // that update again if our traversal picks the objecta again.
                //
                // We also take note that the diskloc if the updates are affecting indices.
                // Chances are that we're traversing one of them and they may be multi key and
                // therefore duplicate disklocs.
                if ( newLoc != loc || driver.modsAffectIndices()  ) {
                    seenLocs.insert( newLoc );
                }
            }

            // Log Obj
            if ( logop ) {
                if ( !logObj.isEmpty() ) {
                    BSONObj pattern = patternOrig;
                    logOp("u", ns, logObj , &pattern, 0, fromMigrate, &newObj );
                }
            }

            // One more document updated.
            numUpdated++;

            if (!multi) {
                break;
            }

            // If we used the cursor mechanism that prepares an earlier seen document for a
            // write we need to tell such mechanisms that the write is over.
            if ( touchPreviousDoc ) {
                cursor->recoverFromTouchingEarlierIterate();
            }

            getDur().commitIfNeeded();

        }

        if (numUpdated > 0) {
            return UpdateResult( true /* updated existing object(s) */,
                                 driver.dollarModMode() /* $mod or obj replacement */,
                                 numUpdated /* # of docments update */,
                                 BSONObj() );
        }
        else if (numUpdated == 0 && !upsert) {
            return UpdateResult( false /* no object updated */,
                                 driver.dollarModMode() /* $mod or obj replacement */,
                                 0 /* no updates */,
                                 BSONObj() );
        }

        //
        // We haven't succeeded updating any existing document but upserts are allowed.
        //

        // If this is a $mod base update, we need to generate a document by examining the
        // query and the mods. Otherwise, we can use the object replacement sent by the user
        // update command that was parsed by the driver before.
        BSONObj oldObj;
        if ( *updateobj.firstElementFieldName() == '$' ) {
            if ( !driver.createFromQuery( patternOrig, &oldObj ) ) {
                uasserted( 16835, "cannot create object to update" );
            }
            debug.fastmodinsert = true;
        }
        else {
            debug.upsert = true;
        }

        // Since this is an upsert, we will be oplogging it as an insert. We don't
        // need the driver's help to build the oplog record, then. We also set the
        // context of the update driver to an "upsert". Some mods may only work in that
        // context (e.g. $setOnInsert).
        driver.setLogOp( false );
        driver.setContext( ModifierInterface::ExecInfo::INSERT_CONTEXT );

        mutablebson::Document doc( oldObj, mutablebson::Document::kInPlaceDisabled );
        status = driver.update( StringData(), &doc, NULL /* no oplog record */);
        if ( !status.isOK() ) {
            uasserted( 16836, status.reason() );
        }
        BSONObj newObj = doc.getObject();

        theDataFileMgr.insertWithObjMod( ns, newObj, false, su );

        if ( logop ) {
            logOp( "i", ns, newObj, 0, 0, fromMigrate, &newObj );
        }

        return UpdateResult( false /* updated a non existing document */,
                             driver.dollarModMode() /* $mod or obj replacement? */,
                             1 /* count of updated documents */,
                             newObj /* object that was upserted */ );
    }

    UpdateResult updateObjects( const char* ns,
                                const BSONObj& updateobj,
                                const BSONObj& patternOrig,
                                bool upsert,
                                bool multi,
                                bool logop ,
                                OpDebug& debug,
                                bool fromMigrate,
                                const QueryPlanSelectionPolicy& planPolicy ) {

        validateUpdate( ns , updateobj , patternOrig );

        if ( isNewUpdateFrameworkEnabled() ) {

            UpdateResult ur = _updateObjectsNEW(false, ns, updateobj, patternOrig,
                                                upsert, multi, logop,
                                                debug, NULL, fromMigrate, planPolicy );
            debug.nupdated = ur.num;
            return ur;
        }
        else {

            UpdateResult ur = _updateObjects(false, ns, updateobj, patternOrig,
                                             upsert, multi, logop,
                                             debug, NULL, fromMigrate, planPolicy );
            debug.nupdated = ur.num;
            return ur;
        }
    }

    UpdateResult updateObjectsForReplication( const char* ns,
                                              const BSONObj& updateobj,
                                              const BSONObj& patternOrig,
                                              bool upsert,
                                              bool multi,
                                              bool logop ,
                                              OpDebug& debug,
                                              bool fromMigrate,
                                              const QueryPlanSelectionPolicy& planPolicy ) {

        validateUpdate( ns , updateobj , patternOrig );

        if ( isNewUpdateFrameworkEnabled() ) {

            UpdateResult ur = _updateObjectsNEW(false,
                                                ns,
                                                updateobj,
                                                patternOrig,
                                                upsert,
                                                multi,
                                                logop,
                                                debug,
                                                NULL /* no remove saver */,
                                                fromMigrate,
                                                planPolicy,
                                                true /* for replication */ );
            debug.nupdated = ur.num;
            return ur;

        }
        else {

            UpdateResult ur = _updateObjects(false,
                                             ns,
                                             updateobj,
                                             patternOrig,
                                             upsert,
                                             multi,
                                             logop,
                                             debug,
                                             NULL /* no remove saver */,
                                             fromMigrate,
                                             planPolicy,
                                             true /* for replication */ );
            debug.nupdated = ur.num;
            return ur;

        }
    }

    BSONObj applyUpdateOperators( const BSONObj& from, const BSONObj& operators ) {
        if ( isNewUpdateFrameworkEnabled() ) {
            UpdateDriver::Options opts;
            opts.multi = false;
            opts.upsert = false;
            UpdateDriver driver( opts );
            Status status = driver.parse( IndexPathSet(), operators );
            if ( !status.isOK() ) {
                uasserted( 16838, status.reason() );
            }

            mutablebson::Document doc( from, mutablebson::Document::kInPlaceDisabled );
            status = driver.update( StringData(), &doc, NULL /* not oplogging */ );
            if ( !status.isOK() ) {
                uasserted( 16839, status.reason() );
            }

            return doc.getObject();
        }
        else {
            ModSet mods( operators );
            return mods.prepare( from, false /* not an insertion */ )->createNewFromMods();
        }
    }

}  // namespace mongo
