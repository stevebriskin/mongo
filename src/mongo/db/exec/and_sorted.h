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

#include <queue>
#include <vector>

#include "mongo/db/diskloc.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/matcher.h"
#include "mongo/db/exec/plan_stage.h"
#include "mongo/platform/unordered_set.h"

namespace mongo {

    /**
     * Reads from N children, each of which must have a valid DiskLoc.  Assumes each child produces
     * DiskLocs in sorted order.  Outputs the intersection of the DiskLocs outputted by the
     * children.
     *
     * Preconditions: Valid DiskLoc.  More than one child.
     *
     * Any DiskLoc that we keep a reference to that is invalidated before we are able to return it
     * is fetched and added to the WorkingSet as "flagged for further review."  Because this stage
     * operates with DiskLocs, we are unable to evaluate the AND for the invalidated DiskLoc, and it
     * must be fully matched later.
     */
    class AndSortedStage : public PlanStage {
    public:
        AndSortedStage(WorkingSet* ws, Matcher* matcher);
        virtual ~AndSortedStage();

        void addChild(PlanStage* child);

        virtual StageState work(WorkingSetID* out);
        virtual bool isEOF();

        virtual void prepareToYield();
        virtual void recoverFromYield();
        virtual void invalidate(const DiskLoc& dl);

    private:
        // Find a node to AND against.
        PlanStage::StageState getTargetLoc();

        // Move a child which hasn't advanced to the target node forward.
        // Returns the target node in 'out' if all children successfully advance to it.
        PlanStage::StageState moveTowardTargetLoc(WorkingSetID* out);

        // Not owned by us.
        WorkingSet* _ws;
        scoped_ptr<Matcher> _matcher;

        // Owned by us.
        vector<PlanStage*> _children;

        // The current node we're AND-ing against.
        PlanStage* _targetNode;
        DiskLoc _targetLoc;
        WorkingSetID _targetId;

        // Nodes we're moving forward until they hit the element we're AND-ing.
        // Everything in here has not advanced to _targetLoc yet.
        std::queue<PlanStage*> _workingTowardRep;

        // If any child hits EOF or if we have any errors, we're EOF.
        bool _isEOF;
    };

}  // namespace mongo
