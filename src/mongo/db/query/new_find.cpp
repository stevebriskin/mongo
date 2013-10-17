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

#include "mongo/db/query/new_find.h"

#include "mongo/client/dbclientinterface.h"
#include "mongo/db/clientcursor.h"
#include "mongo/db/commands.h"
#include "mongo/db/exec/filter.h"
#include "mongo/db/exec/oplogstart.h"
#include "mongo/db/index/catalog_hack.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/keypattern.h"
#include "mongo/db/kill_current_op.h"
#include "mongo/db/matcher/expression.h"
#include "mongo/db/matcher/expression_geo.h"
#include "mongo/db/query/cached_plan_runner.h"
#include "mongo/db/query/canonical_query.h"
#include "mongo/db/query/eof_runner.h"
#include "mongo/db/query/internal_plans.h"
#include "mongo/db/query/multi_plan_runner.h"
#include "mongo/db/query/plan_cache.h"
#include "mongo/db/query/qlog.h"
#include "mongo/db/query/query_planner.h"
#include "mongo/db/query/query_planner_common.h"
#include "mongo/db/query/single_solution_runner.h"
#include "mongo/db/query/stage_builder.h"
#include "mongo/db/query/type_explain.h"
#include "mongo/db/repl/repl_reads_ok.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameters.h"
#include "mongo/db/storage_options.h"
#include "mongo/db/structure/collection.h"
#include "mongo/s/chunk_version.h"
#include "mongo/s/d_logic.h"
#include "mongo/s/stale_exception.h"
#include "mongo/util/mongoutils/str.h"

namespace {

    // Copied from db/ops/query.cpp.  Quote:
    // We cut off further objects once we cross this threshold; thus, you might get
    // a little bit more than this, it is a threshold rather than a limit.
    static const int32_t MaxBytesToReturnToClientAtOnce = 4 * 1024 * 1024;

    // TODO: Remove this or use it.
    bool hasIndexSpecifier(const mongo::LiteParsedQuery& pq) {
        return !pq.getHint().isEmpty() || !pq.getMin().isEmpty() || !pq.getMax().isEmpty();
    }

    /**
     * Quote:
     * if ntoreturn is zero, we return up to 101 objects.  on the subsequent getmore, there
     * is only a size limit.  The idea is that on a find() where one doesn't use much results,
     * we don't return much, but once getmore kicks in, we start pushing significant quantities.
     *
     * The n limit (vs. size) is important when someone fetches only one small field from big
     * objects, which causes massive scanning server-side.
     */
    bool enoughForFirstBatch(const mongo::LiteParsedQuery& pq, int n, int len) {
        if (0 == pq.getNumToReturn()) {
            return (len > 1024 * 1024) || n >= 101;
        }
        return n >= pq.getNumToReturn() || len > MaxBytesToReturnToClientAtOnce;
    }

    bool enough(const mongo::LiteParsedQuery& pq, int n) {
        if (0 == pq.getNumToReturn()) { return false; }
        return n >= pq.getNumToReturn();
    }

    bool enoughForExplain(const mongo::LiteParsedQuery& pq, long long n) {
        if (pq.wantMore() || 0 == pq.getNumToReturn()) { return false; }
        return n >= pq.getNumToReturn();
    }

}  // namespace

namespace mongo {

    // Server parameter
    MONGO_EXPORT_SERVER_PARAMETER(newQueryFrameworkEnabled, bool, true);

    bool isNewQueryFrameworkEnabled() { return newQueryFrameworkEnabled; }
    void enableNewQueryFramework() { newQueryFrameworkEnabled = true; }

    // Do we use the old or the new?  I call this the spigot.
    bool canUseNewSystem(const QueryMessage& qm, CanonicalQuery** cqOut) {
        // This is a read lock.  We require this because if we're parsing a $where, the
        // where-specific parsing code assumes we have a lock and creates execution machinery that
        // requires it.
        Client::ReadContext ctx(qm.ns);

        CanonicalQuery* cq;
        Status status = CanonicalQuery::canonicalize(qm, &cq);
        if (!status.isOK()) { return false; }
        verify(cq);
        auto_ptr<CanonicalQuery> scopedCq(cq);

        const LiteParsedQuery& pq = cq->getParsed();

        // Things we know we fail at:

        // Sort.
        if (!pq.getSort().isEmpty()) {
            // We can deal with this 'cuz it means do a collscan.
            BSONElement natural = pq.getSort().getFieldDotted("$natural");
            if (natural.eoo()) {
                QLOG() << "rejecting query w/sort: " << pq.getSort().toString() << endl;
                return false;
            }
        }

        // Projections.
        if (!pq.getProj().isEmpty()) {
            QLOG() << "rejecting query w/proj\n";
            return false;
        }

        // Negations.
        if (QueryPlannerCommon::hasNode(cq->root(), MatchExpression::NOT)
            || QueryPlannerCommon::hasNode(cq->root(), MatchExpression::NOR)) {

            QLOG() << "rejecting query w/negation\n";
            return false;
        }

        // Obscure arguments to .find().
        if (pq.returnKey() || pq.showDiskLoc() || (0 != pq.getMaxScan()) || !pq.getMin().isEmpty()
            || !pq.getMax().isEmpty()) {
            QLOG() << "rejecting wacky query args query\n";
            return false;
        }

        // 2d-indexed $near.
        MatchExpression* nearNode;
        if (QueryPlannerCommon::hasNode(cq->root(), MatchExpression::GEO_NEAR, &nearNode)) {
            GeoNearMatchExpression* gnme = static_cast<GeoNearMatchExpression*>(nearNode);
            NamespaceDetails* nsd = nsdetails(cq->ns().c_str());
            if (NULL == nsd) {
                // Will create an EOFRunner.
                *cqOut = scopedCq.release();
                return true;
            }
            for (int i = 0; i < nsd->getCompletedIndexCount(); ++i) {
                auto_ptr<IndexDescriptor> desc(CatalogHack::getDescriptor(nsd, i));
                BSONObjIterator kpIt(desc->keyPattern());
                while (kpIt.more()) {
                    BSONElement elt = kpIt.next();
                    // An index over the GEO_NEAR field...
                    if (gnme->getData().field != elt.fieldName()) {
                        continue;
                    }
                    if (String == elt.type() && elt.String() == "2d") {
                        QLOG() << "ignoring 2d geonear\n";
                        return false;
                    }
                }
            }
        }

        *cqOut = scopedCq.release();
        return true;
    }

    /**
     * For a given query, get a runner.  The runner could be a SingleSolutionRunner, a
     * CachedQueryRunner, or a MultiPlanRunner, depending on the cache/query solver/etc.
     */
    Status getRunner(CanonicalQuery* rawCanonicalQuery, Runner** out) {
        verify(rawCanonicalQuery);
        auto_ptr<CanonicalQuery> canonicalQuery(rawCanonicalQuery);

        // Try to look up a cached solution for the query.
        // TODO: Can the cache have negative data about a solution?
        PlanCache* localCache = PlanCache::get(canonicalQuery->ns());
        if (NULL != localCache) {
            CachedSolution* cs = localCache->get(*canonicalQuery);
            if (NULL != cs) {
                // We have a cached solution.  Hand the canonical query and cached solution off to
                // the cached plan runner, which takes ownership of both.
                WorkingSet* ws;
                PlanStage* root;
                verify(StageBuilder::build(*cs->solution, &root, &ws));
                *out = new CachedPlanRunner(canonicalQuery.release(), cs, root, ws);
                return Status::OK();
            }
        }

        // No entry in cache for the query.  We have to solve the query ourself.

        // Get the indices that we could possibly use.
        NamespaceDetails* nsd = nsdetails(canonicalQuery->ns().c_str());

        // Tailable: If the query requests tailable the collection must be capped.
        if (canonicalQuery->getParsed().hasOption(QueryOption_CursorTailable)) {
            if (!nsd->isCapped()) {
                return Status(ErrorCodes::BadValue,
                              "tailable cursor requested on non capped collection");
            }

            // If a sort is specified it must be equal to expectedSort.
            const BSONObj expectedSort = BSON("$natural" << 1);
            const BSONObj& actualSort = canonicalQuery->getParsed().getSort();
            if (!actualSort.isEmpty() && !(actualSort == expectedSort)) {
                return Status(ErrorCodes::BadValue,
                              "invalid sort specified for tailable cursor: "
                              + actualSort.toString());
            }
        }

        // If it's not NULL, we may have indices.
        vector<IndexEntry> indices;
        for (int i = 0; i < nsd->getCompletedIndexCount(); ++i) {
            auto_ptr<IndexDescriptor> desc(CatalogHack::getDescriptor(nsd, i));
            indices.push_back(IndexEntry(desc->keyPattern(), desc->isMultikey(), desc->isSparse(), desc->indexName()));
        }

        vector<QuerySolution*> solutions;
        size_t options = QueryPlanner::DEFAULT;
        if (storageGlobalParams.noTableScan) {
            const string& ns = canonicalQuery->ns();
            // There are certain cases where we ignore this restriction:
            bool ignore = canonicalQuery->getQueryObj().isEmpty()
                          || (string::npos != ns.find(".system."))
                          || (0 == ns.find("local."));
            if (!ignore) {
                options |= QueryPlanner::NO_TABLE_SCAN;
            }
        }
        else {
            options |= QueryPlanner::INCLUDE_COLLSCAN;
        }
        QueryPlanner::plan(*canonicalQuery, indices, options, &solutions);

        /*
        for (size_t i = 0; i < solutions.size(); ++i) {
            QLOG() << "solution " << i << " is " << solutions[i]->toString() << endl;
        }
        */

        // We cannot figure out how to answer the query.  Should this ever happen?
        if (0 == solutions.size()) {
            return Status(ErrorCodes::BadValue, "Can't create a plan for the canonical query " +
                                                 canonicalQuery->toString());
        }

        if (1 == solutions.size()) {
            // Only one possible plan.  Run it.  Build the stages from the solution.
            WorkingSet* ws;
            PlanStage* root;
            verify(StageBuilder::build(*solutions[0], &root, &ws));

            // And, run the plan.
            *out = new SingleSolutionRunner(canonicalQuery.release(), solutions[0], root, ws);
            return Status::OK();
        }
        else {
            // Many solutions.  Let the MultiPlanRunner pick the best, update the cache, and so on.
            auto_ptr<MultiPlanRunner> mpr(new MultiPlanRunner(canonicalQuery.release()));
            for (size_t i = 0; i < solutions.size(); ++i) {
                WorkingSet* ws;
                PlanStage* root;
                verify(StageBuilder::build(*solutions[i], &root, &ws));
                // Takes ownership of all arguments.
                mpr->addPlan(solutions[i], root, ws);
            }
            *out = mpr.release();
            return Status::OK();
        }
    }

    /**
     * Also called by db/ops/query.cpp.  This is the new getMore entry point.
     */
    QueryResult* newGetMore(const char* ns, int ntoreturn, long long cursorid, CurOp& curop,
                            int pass, bool& exhaust, bool* isCursorAuthorized) {
        exhaust = false;
        int bufSize = 512 + sizeof(QueryResult) + MaxBytesToReturnToClientAtOnce;

        BufBuilder bb(bufSize);
        bb.skip(sizeof(QueryResult));

        // This is a read lock.  TODO: There is a cursor flag for not needing this.  Do we care?
        Client::ReadContext ctx(ns);

        QLOG() << "running getMore in new system, cursorid " << cursorid << endl;

        // This checks to make sure the operation is allowed on a replicated node.  Since we are not
        // passing in a query object (necessary to check SlaveOK query option), the only state where
        // reads are allowed is PRIMARY (or master in master/slave).  This function uasserts if
        // reads are not okay.
        replVerifyReadsOk();

        // A pin performs a CC lookup and if there is a CC, increments the CC's pin value so it
        // doesn't time out.  Also informs ClientCursor that there is somebody actively holding the
        // CC, so don't delete it.
        ClientCursorPin ccPin(cursorid);
        ClientCursor* cc = ccPin.c();

        // These are set in the QueryResult msg we return.
        int resultFlags = ResultFlag_AwaitCapable;

        int numResults = 0;
        int startingResult = 0;

        if (NULL == cc) {
            cursorid = 0;
            resultFlags = ResultFlag_CursorNotFound;
        }
        else {
            // Quote: check for spoofing of the ns such that it does not match the one originally
            // there for the cursor
            uassert(17011, "auth error", str::equals(ns, cc->ns().c_str()));
            *isCursorAuthorized = true;

            // TODO: fail point?

            // If the operation that spawned this cursor had a time limit set, apply leftover
            // time to this getmore.
            curop.setMaxTimeMicros(cc->getLeftoverMaxTimeMicros());
            killCurrentOp.checkForInterrupt(); // May trigger maxTimeAlwaysTimeOut fail point.

            // TODO:
            // curop.debug().query = BSONForQuery
            // curop.setQuery(curop.debug().query);

            // TODO: What is pass?
            if (0 == pass) { cc->updateSlaveLocation(curop); }

            CollectionMetadataPtr collMetadata = cc->getCollMetadata();

            // If we're replaying the oplog, we save the last time that we read.
            OpTime slaveReadTill;

            // What number result are we starting at?  Used to fill out the reply.
            startingResult = cc->pos();

            // What gives us results.
            Runner* runner = cc->getRunner();
            const int queryOptions = cc->queryOptions();

            // Get results out of the runner.
            runner->restoreState();

            BSONObj obj;
            Runner::RunnerState state;
            while (Runner::RUNNER_ADVANCED == (state = runner->getNext(&obj, NULL))) {
                // If we're sharded make sure that we don't return any data that hasn't been
                // migrated off of our shard yet.
                if (collMetadata) {
                    KeyPattern kp(collMetadata->getKeyPattern());
                    if (!collMetadata->keyBelongsToMe(kp.extractSingleKey(obj))) { continue; }
                }

                // Add result to output buffer.
                bb.appendBuf((void*)obj.objdata(), obj.objsize());

                // Count the result.
                ++numResults;

                // Possibly note slave's position in the oplog.
                if (queryOptions & QueryOption_OplogReplay) {
                    BSONElement e = obj["ts"];
                    if (Date == e.type() || Timestamp == e.type()) {
                        slaveReadTill = e._opTime();
                    }
                }

                if ((ntoreturn && numResults >= ntoreturn)
                    || bb.len() > MaxBytesToReturnToClientAtOnce) {
                    break;
                }
            }

            if (Runner::RUNNER_EOF == state && 0 == numResults
                && (queryOptions & QueryOption_CursorTailable)
                && (queryOptions & QueryOption_AwaitData) && (pass < 1000)) {
                // If the cursor is tailable we don't kill it if it's eof.  We let it try to get
                // data some # of times first.
                return 0;
            }

            bool saveClientCursor = false;

            if (Runner::RUNNER_DEAD == state || Runner::RUNNER_ERROR == state) {
                // If we're dead there's no way to get more results.
                saveClientCursor = false;
                // In the old system tailable capped cursors would be killed off at the
                // cursorid level.  If a tailable capped cursor is nuked the cursorid
                // would vanish.
                // 
                // In the new system they die and are cleaned up later (or time out).
                // So this is where we get to remove the cursorid.
                if (0 == numResults) {
                    resultFlags = ResultFlag_CursorNotFound;
                }
            }
            else if (Runner::RUNNER_EOF == state) {
                // EOF is also end of the line unless it's tailable.
                saveClientCursor = queryOptions & QueryOption_CursorTailable;
            }
            else {
                verify(Runner::RUNNER_ADVANCED == state);
                saveClientCursor = true;
            }

            if (!saveClientCursor) {
                ccPin.free();
                // cc is now invalid, as is the runner
                cursorid = 0;
                cc = NULL;
                QLOG() << "getMore NOT saving client cursor, ended w/state "
                       << Runner::statestr(state)
                       << endl;
            }
            else {
                // Continue caching the ClientCursor.
                cc->incPos(numResults);
                runner->saveState();
                QLOG() << "getMore saving client cursor ended w/state "
                       << Runner::statestr(state)
                       << endl;

                // Possibly note slave's position in the oplog.
                if ((queryOptions & QueryOption_OplogReplay) && !slaveReadTill.isNull()) {
                    cc->slaveReadTill(slaveReadTill);
                }

                exhaust = (queryOptions & QueryOption_Exhaust);

                // If the getmore had a time limit, remaining time is "rolled over" back to the
                // cursor (for use by future getmore ops).
                cc->setLeftoverMaxTimeMicros( curop.getRemainingMaxTimeMicros() );
            }
        }

        QueryResult* qr = reinterpret_cast<QueryResult*>(bb.buf());
        qr->len = bb.len();
        qr->setOperation(opReply);
        qr->_resultFlags() = resultFlags;
        qr->cursorId = cursorid;
        qr->startingFrom = startingResult;
        qr->nReturned = numResults;
        bb.decouple();
        QLOG() << "getMore returned " << numResults << " results\n";
        return qr;
    }

    /**
     * RAII approach to ensuring that runners are deregistered in newRunQuery.
     *
     * While retrieving the first bach of results, newRunQuery manually registers the runner with
     * ClientCursor.  Certain query execution paths, namely $where, can throw an exception.  If we
     * fail to deregister the runner, we will call invalidate/kill on the
     * still-registered-yet-deleted runner.
     *
     * For any subsequent calls to getMore, the runner is already registered with ClientCursor
     * by virtue of being cached, so this exception-proofing is not required.
     */
    struct DeregisterEvenIfUnderlyingCodeThrows {
        DeregisterEvenIfUnderlyingCodeThrows(Runner* runner) : _runner(runner) { }
        ~DeregisterEvenIfUnderlyingCodeThrows() {
            ClientCursor::deregisterRunner(_runner);
        }
        Runner* _runner;
    };

    Status getOplogStartHack(CanonicalQuery* cq, Runner** runnerOut) {
        // Make an oplog start finding stage.
        WorkingSet* oplogws = new WorkingSet();
        OplogStart* stage = new OplogStart(cq->ns(), cq->root(), oplogws);

        // Takes ownership of ws and stage.
        auto_ptr<InternalRunner> runner(new InternalRunner(cq->ns(), stage, oplogws));
        runner->setYieldPolicy(Runner::YIELD_AUTO);

        // The stage returns a DiskLoc of where to start.
        DiskLoc startLoc;
        Runner::RunnerState state = runner->getNext(NULL, &startLoc);

        // This is normal.  The start of the oplog is the beginning of the collection.
        if (Runner::RUNNER_EOF == state) { return getRunner(cq, runnerOut); }

        // This is not normal.  An error was encountered.
        if (Runner::RUNNER_ADVANCED != state) {
            return Status(ErrorCodes::InternalError,
                          "quick oplog start location had error...?");
        }

        // cout << "diskloc is " << startLoc.toString() << endl;

        // Build our collection scan...
        CollectionScanParams params;
        params.ns = cq->ns();
        params.start = startLoc;
        params.direction = CollectionScanParams::FORWARD;
        params.tailable = cq->getParsed().hasOption(QueryOption_CursorTailable);

        WorkingSet* ws = new WorkingSet();
        CollectionScan* cs = new CollectionScan(params, ws, cq->root());
        // Takes ownership of cq, cs, ws.
        *runnerOut = new SingleSolutionRunner(cq, NULL, cs, ws);
        return Status::OK();
    }

    /**
     * This is called by db/ops/query.cpp.  This is the entry point for answering a query.
     */
    std::string newRunQuery(CanonicalQuery* cq, CurOp& curop, Message &result) {
        QLOG() << "Running query on new system: " << cq->toString();

        // This is a read lock.
        Client::ReadContext ctx(cq->ns(), storageGlobalParams.dbpath);

        // Parse, canonicalize, plan, transcribe, and get a runner.
        Runner* rawRunner = NULL;

        // We use this a lot below.
        const LiteParsedQuery& pq = cq->getParsed();

        // Need to call cq->toString() now, since upon error getRunner doesn't guarantee
        // cq is in a consistent state.
        string cqStr = cq->toString();

        // We'll now try to get the query runner that will execute this query for us. There
        // are a few cases in which we know upfront which runner we should get and, therefore,
        // we shortcut the selection process here.
        //
        // (a) If the query is over a collection that doesn't exist, we get a special runner
        // that's is so (a runner) which doesn't return results, the EOFRunner.
        //
        // (b) if the query is a replication's initial sync one, we get a SingleSolutinRunner
        // that uses a specifically designed stage that skips extents faster (see details in
        // exec/oplogstart.h)
        //
        // Otherwise we go through the selection of which runner is most suited to the
        // query + run-time context at hand.
        Status status = Status::OK();
        if (ctx.ctx().db()->getCollection(cq->ns()) == NULL) {
            rawRunner = new EOFRunner(cq, cq->ns());
        }
        else if (pq.hasOption(QueryOption_OplogReplay)) {
            status = getOplogStartHack(cq, &rawRunner);
        }
        else {
            // Takes ownership of cq.
            status = getRunner(cq, &rawRunner);
        }

        if (!status.isOK()) {
            uasserted(17007, "Couldn't process query " + cqStr + " why: " + status.reason());
        }

        verify(NULL != rawRunner);
        auto_ptr<Runner> runner(rawRunner);

        // We freak out later if this changes before we're done with the query.
        const ChunkVersion shardingVersionAtStart = shardingState.getVersion(cq->ns());

        // Handle query option $maxTimeMS (not used with commands).
        curop.setMaxTimeMicros(static_cast<unsigned long long>(pq.getMaxTimeMS()) * 1000);
        killCurrentOp.checkForInterrupt(); // May trigger maxTimeAlwaysTimeOut fail point.

        // uassert if we are not on a primary, and not a secondary with SlaveOk query parameter set.
        replVerifyReadsOk(&pq);

        // If this exists, the collection is sharded.
        // If it doesn't exist, we can assume we're not sharded.
        // If we're sharded, we might encounter data that is not consistent with our sharding state.
        // We must ignore this data.
        CollectionMetadataPtr collMetadata;
        if (!shardingState.needCollectionMetadata(pq.ns())) {
            collMetadata = CollectionMetadataPtr();
        }
        else {
            collMetadata = shardingState.getCollectionMetadata(pq.ns());
        }

        // Run the query.
        // bb is used to hold query results
        // this buffer should contain either requested documents per query or
        // explain information, but not both
        BufBuilder bb(32768);
        bb.skip(sizeof(QueryResult));

        // How many results have we obtained from the runner?
        int numResults = 0;

        // If we're replaying the oplog, we save the last time that we read.
        OpTime slaveReadTill;

        // Do we save the Runner in a ClientCursor for getMore calls later?
        bool saveClientCursor = false;

        // We turn on auto-yielding for the runner here.  The runner registers itself with the
        // active runners list in ClientCursor.
        ClientCursor::registerRunner(runner.get());
        runner->setYieldPolicy(Runner::YIELD_AUTO);
        auto_ptr<DeregisterEvenIfUnderlyingCodeThrows> safety(
            new DeregisterEvenIfUnderlyingCodeThrows(runner.get()));

        BSONObj obj;
        Runner::RunnerState state;
        uint64_t numMisplacedDocs = 0;

        // set this outside loop. we will need to use this both within loop and when deciding
        // to fill in explain information
        const bool isExplain = pq.isExplain();

        while (Runner::RUNNER_ADVANCED == (state = runner->getNext(&obj, NULL))) {
            // cout << "pulled out of runner: " << obj.toString() << endl;

            // If we're sharded make sure that we don't return any data that hasn't been migrated
            // off of our shared yet.
            if (collMetadata) {
                // This information can change if we yield and as such we must make sure to re-fetch
                // it if we yield.
                KeyPattern kp(collMetadata->getKeyPattern());
                // This performs excessive BSONObj creation but that's OK for now.
                if (!collMetadata->keyBelongsToMe(kp.extractSingleKey(obj))) {
                    ++numMisplacedDocs;
                    continue;
                }
            }

            // Add result to output buffer. This is unnecessary if explain info is requested
            if (!isExplain) {
                bb.appendBuf((void*)obj.objdata(), obj.objsize());
            }

            // Count the result.
            ++numResults;

            // Possibly note slave's position in the oplog.
            if (pq.hasOption(QueryOption_OplogReplay)) {
                BSONElement e = obj["ts"];
                if (Date == e.type() || Timestamp == e.type()) {
                    slaveReadTill = e._opTime();
                }
            }

            // TODO: only one type of 2d search doesn't support this.  We need a way to pull it out
            // of CanonicalQuery. :(
            const bool supportsGetMore = true;
            if (isExplain) {
                if (enoughForExplain(pq, numResults)) {
                    break;
                }
            }
            else if (!supportsGetMore && (enough(pq, numResults)
                                          || bb.len() >= MaxBytesToReturnToClientAtOnce)) {
                break;
            }
            else if (enoughForFirstBatch(pq, numResults, bb.len())) {
                QLOG() << "Enough for first batch, wantMore=" << pq.wantMore()
                       << " numToReturn=" << pq.getNumToReturn()
                       << " numResults=" << numResults
                       << endl;
                // If only one result requested assume it's a findOne() and don't save the cursor.
                if (pq.wantMore() && 1 != pq.getNumToReturn()) {
                    QLOG() << " runner EOF=" << runner->isEOF() << endl;
                    saveClientCursor = !runner->isEOF();
                }
                break;
            }
        }

        // If we cache the runner later, we want to deregister it as it receives notifications
        // anyway by virtue of being cached.
        //
        // If we don't cache the runner later, we are deleting it, so it must be deregistered.
        //
        // So, no matter what, deregister the runner.
        safety.reset();

        // Caller expects exceptions thrown in certain cases:
        // * in-memory sort using too much RAM.
        if (Runner::RUNNER_ERROR == state) {
            uasserted(17144, "Runner error, memory limit for sort probably exceeded");
        }

        // Why save a dead runner?
        if (Runner::RUNNER_DEAD == state) {
            saveClientCursor = false;
        }
        else if (pq.hasOption(QueryOption_CursorTailable)) {
            // If we're tailing a capped collection, we don't bother saving the cursor if the
            // collection is empty. Otherwise, the semantics of the tailable cursor is that the
            // client will keep trying to read from it. So we'll keep it around.
            Collection* collection = ctx.ctx().db()->getCollection(cq->ns());
            if (collection->numRecords() != 0 && pq.getNumToReturn() != 1) {
                saveClientCursor = true;
            }
        }

        // TODO(greg): This will go away soon.
        if (!shardingState.getVersion(pq.ns()).isWriteCompatibleWith(shardingVersionAtStart)) {
            // if the version changed during the query we might be missing some data and its safe to
            // send this as mongos can resend at this point
            throw SendStaleConfigException(pq.ns(), "version changed during initial query",
                                           shardingVersionAtStart,
                                           shardingState.getVersion(pq.ns()));
        }

        // Append explain information to query results by asking the runner to produce them.
        if (isExplain) {
            TypeExplain* bareExplain;
            Status res = runner->getExplainPlan(&bareExplain);

            if (!res.isOK()) {
                error() << "could not produce explain of query '" << pq.getFilter()
                        << "', error: " << res.reason();
                // If numResults and the data in bb don't correspond, we'll crash later when rooting
                // through the reply msg.
                BSONObj emptyObj;
                bb.appendBuf((void*)emptyObj.objdata(), emptyObj.objsize());
                // The explain output is actually a result.
                numResults = 1;
                // TODO: we can fill out millis etc. here just fine even if the plan screwed up.
            }
            else {
                boost::scoped_ptr<TypeExplain> explain(bareExplain);

                // Fill in the missing run-time fields in explain, starting with propeties of
                // the process running the query.
                std::string server = mongoutils::str::stream()
                    << getHostNameCached() << ":" << serverGlobalParams.port;
                explain->setServer(server);

                // We might have skipped some results due to chunk migration etc. so our count is
                // correct.
                explain->setN(numResults);

                // Fill in the number of documents consummed that were involved in an ongoing
                // (or aborted) migration.
                explain->setNChunkSkips(numMisplacedDocs);

                // We might have skipped some results due to chunk migration etc. so our count is
                // correct and explain's is not.
                explain->setN(numResults);

                // Clock the whole operation.
                explain->setMillis(curop.elapsedMillis());

                BSONObj explainObj = explain->toBSON();
                bb.appendBuf((void*)explainObj.objdata(), explainObj.objsize());

                // The explain output is actually a result.
                numResults = 1;
            }
        }

        long long ccId = 0;
        if (saveClientCursor) {
            // We won't use the runner until it's getMore'd.
            runner->saveState();

            // Allocate a new ClientCursor.  We don't have to worry about leaking it as it's
            // inserted into a global map by its ctor.
            ClientCursor* cc = new ClientCursor(runner.get(), cq->getParsed().getOptions(),
                                                cq->getParsed().getFilter());
            ccId = cc->cursorid();

            QLOG() << "caching runner with cursorid " << ccId
                   << " after returning " << numResults << " results" << endl;

            // ClientCursor takes ownership of runner.  Release to make sure it's not deleted.
            runner.release();

            // TODO document
            if (pq.hasOption(QueryOption_OplogReplay) && !slaveReadTill.isNull()) {
                cc->slaveReadTill(slaveReadTill);
            }

            // TODO document
            if (pq.hasOption(QueryOption_Exhaust)) {
                curop.debug().exhaust = true;
            }

            // Set attributes for getMore.
            cc->setCollMetadata(collMetadata);
            cc->setPos(numResults);

            // If the query had a time limit, remaining time is "rolled over" to the cursor (for
            // use by future getmore ops).
            cc->setLeftoverMaxTimeMicros(curop.getRemainingMaxTimeMicros());
        }
        else {
            QLOG() << "not caching runner but returning " << numResults << " results\n";
        }

        // Add the results from the query into the output buffer.
        result.appendData(bb.buf(), bb.len());
        bb.decouple();

        // Fill out the output buffer's header.
        QueryResult* qr = static_cast<QueryResult*>(result.header());
        qr->cursorId = ccId;
        curop.debug().cursorid = (0 == ccId ? -1 : ccId);
        qr->setResultFlagsToOk();
        qr->setOperation(opReply);
        qr->startingFrom = 0;
        qr->nReturned = numResults;

        curop.debug().ntoskip = pq.getSkip();
        curop.debug().nreturned = numResults;

        // curop.debug().exhaust is set above.
        return curop.debug().exhaust ? pq.ns() : "";
    }

}  // namespace mongo
