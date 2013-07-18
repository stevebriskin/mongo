/**
 *    Copyright (C) 2012 10gen Inc.
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

#include "mongo/s/collection_metadata.h"

#include "mongo/bson/util/builder.h" // for StringBuilder
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    using mongoutils::str::stream;

    CollectionMetadata::CollectionMetadata() { }

    CollectionMetadata::~CollectionMetadata() { }

    CollectionMetadata* CollectionMetadata::cloneMinusChunk( const ChunkType& chunk,
                                                             const ChunkVersion& newShardVersion,
                                                             string* errMsg ) const {
        // The error message string is optional.
        string dummy;
        if (errMsg == NULL) {
            errMsg = &dummy;
        }

        // Check that we have the exact chunk that will be subtracted.
        if ( !rangeMapContains( _chunksMap, chunk.getMin(), chunk.getMax() ) ) {

            *errMsg = stream() << "cannot remove chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << ", this shard does not contain the chunk";

            if ( rangeMapOverlaps( _chunksMap, chunk.getMin(), chunk.getMax() ) ) {

                RangeVector overlap;
                getRangeMapOverlap( _chunksMap, chunk.getMin(), chunk.getMax(), &overlap );

                *errMsg += stream() << " and it overlaps " << overlapToString( overlap );
            }

            warning() << *errMsg << endl;
            return NULL;
        }

        // If left with no chunks, check that the version is zero.
        if (_chunksMap.size() == 1) {
            if (newShardVersion.isSet()) {

                *errMsg = stream() << "cannot set shard version to non-zero value "
                                   << newShardVersion.toString() << " when removing last chunk "
                                   << rangeToString( chunk.getMin(), chunk.getMax() );

                warning() << *errMsg << endl;
                return NULL;
            }
        }
        // Can't move version backwards when subtracting chunks.  This is what guarantees that
        // no read or write would be taken once we subtract data from the current shard.
        else if (newShardVersion <= _shardVersion) {

            *errMsg = stream() << "cannot remove chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << " because the new shard version " << newShardVersion.toString()
                               << " is not greater than the current shard version "
                               << _shardVersion.toString();

            warning() << *errMsg << endl;
            return NULL;
        }

        auto_ptr<CollectionMetadata> metadata( new CollectionMetadata );
        metadata->_keyPattern = this->_keyPattern;
        metadata->_keyPattern.getOwned();
        metadata->_pendingMap = this->_pendingMap;
        metadata->_chunksMap = this->_chunksMap;
        metadata->_chunksMap.erase( chunk.getMin() );
        metadata->_shardVersion = newShardVersion;
        metadata->_collVersion =
                newShardVersion > _collVersion ? newShardVersion : this->_collVersion;
        metadata->fillRanges();

        dassert(metadata->isValid());
        return metadata.release();
    }

    CollectionMetadata* CollectionMetadata::clonePlusChunk( const ChunkType& chunk,
                                                            const ChunkVersion& newShardVersion,
                                                            string* errMsg ) const {
        // The error message string is optional.
        string dummy;
        if (errMsg == NULL) {
            errMsg = &dummy;
        }

        // It is acceptable to move version backwards (e.g., undoing a migration that went bad
        // during commit) but only cloning away the last chunk may reset the version to 0.
        if (!newShardVersion.isSet()) {

            *errMsg = stream() << "cannot add chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << " with zero shard version";

            warning() << *errMsg << endl;
            return NULL;
        }

        // Check that there isn't any chunk on the interval to be added.
        if ( rangeMapOverlaps( _chunksMap, chunk.getMin(), chunk.getMax() ) ) {

            RangeVector overlap;
            getRangeMapOverlap( _chunksMap, chunk.getMin(), chunk.getMax(), &overlap );

            *errMsg = stream() << "cannot add chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << " because the chunk overlaps " << overlapToString( overlap );

            warning() << *errMsg << endl;
            return NULL;
        }

        auto_ptr<CollectionMetadata> metadata( new CollectionMetadata );
        metadata->_keyPattern = this->_keyPattern;
        metadata->_keyPattern.getOwned();
        metadata->_pendingMap = this->_pendingMap;
        metadata->_chunksMap = this->_chunksMap;
        metadata->_chunksMap.insert( make_pair( chunk.getMin().getOwned(),
                                                chunk.getMax().getOwned() ) );
        metadata->_shardVersion = newShardVersion;
        metadata->_collVersion =
                newShardVersion > _collVersion ? newShardVersion : this->_collVersion;
        metadata->fillRanges();

        dassert(metadata->isValid());
        return metadata.release();
    }

    CollectionMetadata* CollectionMetadata::cloneMinusPending( const ChunkType& pending,
                                                               string* errMsg ) const {
        // The error message string is optional.
        string dummy;
        if ( errMsg == NULL ) {
            errMsg = &dummy;
        }

        // Check that we have the exact chunk that will be subtracted.
        if ( !rangeMapContains( _pendingMap, pending.getMin(), pending.getMax() ) ) {

            *errMsg = stream() << "cannot remove pending chunk "
                               << rangeToString( pending.getMin(), pending.getMax() )
                               << ", this shard does not contain the chunk";

            if ( rangeMapOverlaps( _pendingMap, pending.getMin(), pending.getMax() ) ) {

                RangeVector overlap;
                getRangeMapOverlap( _pendingMap, pending.getMin(), pending.getMax(), &overlap );

                *errMsg += stream() << " and it overlaps " << overlapToString( overlap );
            }

            warning() << *errMsg << endl;
            return NULL;
        }

        auto_ptr<CollectionMetadata> metadata( new CollectionMetadata );
        metadata->_keyPattern = this->_keyPattern;
        metadata->_keyPattern.getOwned();
        metadata->_pendingMap = this->_pendingMap;
        metadata->_pendingMap.erase( pending.getMin() );
        metadata->_chunksMap = this->_chunksMap;
        metadata->_rangesMap = this->_rangesMap;
        metadata->_shardVersion = _shardVersion;
        metadata->_collVersion = _collVersion;

        dassert(metadata->isValid());
        return metadata.release();
    }

    CollectionMetadata* CollectionMetadata::clonePlusPending( const ChunkType& pending,
                                                              string* errMsg ) const {
        // The error message string is optional.
        string dummy;
        if ( errMsg == NULL ) {
            errMsg = &dummy;
        }

        if ( rangeMapOverlaps( _chunksMap, pending.getMin(), pending.getMax() ) ) {

            RangeVector overlap;
            getRangeMapOverlap( _chunksMap, pending.getMin(), pending.getMax(), &overlap );

            *errMsg = stream() << "cannot add pending chunk "
                               << rangeToString( pending.getMin(), pending.getMax() )
                               << " because the chunk overlaps " << overlapToString( overlap );

            warning() << *errMsg << endl;
            return NULL;
        }

        auto_ptr<CollectionMetadata> metadata( new CollectionMetadata );
        metadata->_keyPattern = this->_keyPattern;
        metadata->_keyPattern.getOwned();
        metadata->_pendingMap = this->_pendingMap;
        metadata->_chunksMap = this->_chunksMap;
        metadata->_rangesMap = this->_rangesMap;
        metadata->_shardVersion = _shardVersion;
        metadata->_collVersion = _collVersion;

        // If there are any pending chunks on the interval to be added this is ok, since pending
        // chunks aren't officially tracked yet and something may have changed on servers we do not
        // see yet.
        // We remove any chunks we overlap, the remote request starting a chunk migration must have
        // been authoritative.

        if ( rangeMapOverlaps( _pendingMap, pending.getMin(), pending.getMax() ) ) {

            RangeVector pendingOverlap;
            getRangeMapOverlap( _pendingMap, pending.getMin(), pending.getMax(), &pendingOverlap );

            warning() << "new pending chunk " << rangeToString( pending.getMin(), pending.getMax() )
                      << " overlaps existing pending chunks " << overlapToString( pendingOverlap )
                      << ", a migration may not have completed" << endl;

            for ( RangeVector::iterator it = pendingOverlap.begin(); it != pendingOverlap.end();
                    ++it ) {
                metadata->_pendingMap.erase( it->first );
            }
        }

        metadata->_pendingMap.insert( make_pair( pending.getMin(), pending.getMax() ) );

        dassert(metadata->isValid());
        return metadata.release();
    }

    CollectionMetadata* CollectionMetadata::cloneSplit( const ChunkType& chunk,
                                                        const vector<BSONObj>& splitKeys,
                                                        const ChunkVersion& newShardVersion,
                                                        string* errMsg ) const {
        // The error message string is optional.
        string dummy;
        if (errMsg == NULL) {
            errMsg = &dummy;
        }

        // The version required in both resulting chunks could be simply an increment in the
        // minor portion of the current version.  However, we are enforcing uniqueness over the
        // attributes <ns, version> of the configdb collection 'chunks'.  So in practice, a
        // migrate somewhere may force this split to pick up a version that has the major
        // portion higher than the one that this shard has been using.
        //
        // TODO drop the uniqueness constraint and tighten the check below so that only the
        // minor portion of version changes
        if (newShardVersion <= _shardVersion) {

            *errMsg = stream() << "cannot split chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << ", new shard version "
                               << newShardVersion.toString()
                               << " is not greater than current version "
                               << _shardVersion.toString();

            warning() << *errMsg << endl;
            return NULL;
        }

        // Check that we have the exact chunk that will be subtracted.
        if ( !rangeMapContains( _chunksMap, chunk.getMin(), chunk.getMax() ) ) {

            *errMsg = stream() << "cannot split chunk "
                               << rangeToString( chunk.getMin(), chunk.getMax() )
                               << ", this shard does not contain the chunk";

            if ( rangeMapOverlaps( _chunksMap, chunk.getMin(), chunk.getMax() ) ) {

                RangeVector overlap;
                getRangeMapOverlap( _chunksMap, chunk.getMin(), chunk.getMax(), &overlap );

                *errMsg += stream() << " and it overlaps " << overlapToString( overlap );
            }

            warning() << *errMsg << endl;
            return NULL;
        }

        // Check that the split key is valid
        for ( vector<BSONObj>::const_iterator it = splitKeys.begin(); it != splitKeys.end(); ++it )
        {
            if (!rangeContains(chunk.getMin(), chunk.getMax(), *it)) {

                *errMsg = stream() << "cannot split chunk "
                                   << rangeToString( chunk.getMin(), chunk.getMax() ) << " at key "
                                   << *it;

                warning() << *errMsg << endl;
                return NULL;
            }
        }

        auto_ptr<CollectionMetadata> metadata(new CollectionMetadata);
        metadata->_keyPattern = this->_keyPattern;
        metadata->_keyPattern.getOwned();
        metadata->_pendingMap = this->_pendingMap;
        metadata->_chunksMap = this->_chunksMap;
        metadata->_shardVersion = newShardVersion; // will increment 2nd, 3rd,... chunks below

        BSONObj startKey = chunk.getMin();
        for ( vector<BSONObj>::const_iterator it = splitKeys.begin(); it != splitKeys.end();
                ++it ) {
            BSONObj split = *it;
            metadata->_chunksMap[chunk.getMin()] = split.getOwned();
            metadata->_chunksMap.insert( make_pair( split.getOwned(), chunk.getMax().getOwned() ) );
            metadata->_shardVersion.incMinor();
            startKey = split;
        }

        metadata->_collVersion =
                metadata->_shardVersion > _collVersion ? metadata->_shardVersion : _collVersion;
        metadata->fillRanges();

        dassert(metadata->isValid());
        return metadata.release();
    }

    bool CollectionMetadata::keyBelongsToMe( const BSONObj& key ) const {
        // For now, collections don't move. So if the collection is not sharded, assume
        // the document with the given key can be accessed.
        if ( _keyPattern.isEmpty() ) {
            return true;
        }

        if ( _rangesMap.size() <= 0 ) {
            return false;
        }

        RangeMap::const_iterator it = _rangesMap.upper_bound( key );
        if ( it != _rangesMap.begin() ) it--;

        bool good = rangeContains( it->first, it->second, key );

#ifdef _DEBUG
        // Logs if in debugging mode and the point doesn't belong here.
        if ( !good ) {
            log() << "bad: " << key << " " << it->first << " " << key.woCompare( it->first ) << " "
                  << key.woCompare( it->second ) << endl;

            for ( RangeMap::const_iterator i = _rangesMap.begin(); i != _rangesMap.end(); ++i ) {
                log() << "\t" << i->first << "\t" << i->second << "\t" << endl;
            }
        }
#endif

        return good;
    }

    bool CollectionMetadata::keyIsPending( const BSONObj& key ) const {
        // If we aren't sharded, then the key is never pending (though it belongs-to-me)
        if ( _keyPattern.isEmpty() ) {
            return false;
        }

        if ( _pendingMap.size() <= 0 ) {
            return false;
        }

        RangeMap::const_iterator it = _pendingMap.upper_bound( key );
        if ( it != _pendingMap.begin() ) it--;

        bool isPending = rangeContains( it->first, it->second, key );
        return isPending;
    }

    bool CollectionMetadata::getNextChunk(const BSONObj& lookupKey,
                                         ChunkType* chunk) const {
        if (_chunksMap.empty()) {
            return true;
        }

        RangeMap::const_iterator it;
        if (lookupKey.isEmpty()) {
            it = _chunksMap.begin();
            chunk->setMin(it->first);
            chunk->setMax(it->second);
            return _chunksMap.size() == 1;
        }

        it = _chunksMap.upper_bound(lookupKey);
        if (it != _chunksMap.end()) {
            chunk->setMin(it->first);
            chunk->setMax(it->second);
            return false;
        }

        return true;
    }

    string CollectionMetadata::toString() const {
        StringBuilder ss;
        ss << " CollectionManager version: " << _shardVersion.toString() << " key: " << _keyPattern;
        if (_rangesMap.empty()) {
            return ss.str();
        }

        RangeMap::const_iterator it = _rangesMap.begin();
        ss << it->first << " -> " << it->second;
        while (it != _rangesMap.end()) {
            ss << ", "<< it->first << " -> " << it->second;
        }
        return ss.str();
    }

    bool CollectionMetadata::isValid() const {
        if (_shardVersion > _collVersion) {
            return false;
        }

        if (_collVersion.majorVersion() == 0)
            return false;

        return true;
    }

    void CollectionMetadata::fillRanges() {
        if (_chunksMap.empty())
            return;

        // Load the chunk information, coallesceing their ranges.  The version for this shard
        // would be the highest version for any of the chunks.
        RangeMap::const_iterator it = _chunksMap.begin();
        BSONObj min,max;
        while (it != _chunksMap.end()) {
            BSONObj currMin = it->first;
            BSONObj currMax = it->second;
            ++it;

            // coalesce the chunk's bounds in ranges if they are adjacent chunks
            if (min.isEmpty()) {
                min = currMin;
                max = currMax;
                continue;
            }
            if (max == currMin) {
                max = currMax;
                continue;
            }

            _rangesMap.insert(make_pair(min, max));

            min = currMin;
            max = currMax;
        }
        dassert(!min.isEmpty());

        _rangesMap.insert(make_pair(min, max));
    }

    string CollectionMetadata::rangeToString( const BSONObj& inclusiveLower,
                                              const BSONObj& exclusiveUpper ) const {
        stringstream ss;
        ss << "[" << inclusiveLower.toString() << ", " << exclusiveUpper.toString() << ")";
        return ss.str();
    }

    string CollectionMetadata::overlapToString( RangeVector overlap ) const {
        stringstream ss;
        for ( RangeVector::const_iterator it = overlap.begin(); it != overlap.end(); ++it ) {
            if ( it != overlap.begin() ) ss << ", ";
            ss << rangeToString( it->first, it->second );
        }
        return ss.str();
    }

} // namespace mongo
