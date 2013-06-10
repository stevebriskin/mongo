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

#include "mongo/db/ops/modifier_object_replace.h"

#include "mongo/base/error_codes.h"
#include "mongo/bson/mutable/document.h"

namespace mongo {

    struct ModifierObjectReplace::PreparedState {

        PreparedState(mutablebson::Document* targetDoc) : doc(*targetDoc) {}

        // Document that is going to be changed
        mutablebson::Document& doc;

    };

    ModifierObjectReplace::ModifierObjectReplace() : _val() {
    }

    ModifierObjectReplace::~ModifierObjectReplace() {
    }

    Status ModifierObjectReplace::init(const BSONElement& modExpr) {

        if (modExpr.type() != Object) {
            return Status(ErrorCodes::BadValue, "object replace expects full object");
        }

        BSONObjIterator it(modExpr.embeddedObject());
        while (it.moreWithEOO()) {
            BSONElement elem = it.next();
            if (elem.eoo()) {
                break;
            }
            else if (*elem.fieldName() == '$') {
                return Status(ErrorCodes::BadValue, "can't mix modifiers and non-modifiers");
            }
        }

        // TODO: update timestamps?

        // We make a copy of the object here because the update driver does not guarantees, in
        // the case of object replacement, that the modExpr is going to outlive this mod.
        _val = modExpr.embeddedObject().getOwned();

        return Status::OK();
    }

    Status ModifierObjectReplace::prepare(mutablebson::Element root,
                                          const StringData& matchedField,
                                          ExecInfo* execInfo) {

        _preparedState.reset(new PreparedState(&root.getDocument()));
        return Status::OK();
    }

    Status ModifierObjectReplace::apply() const {

        // Remove the contents of the provided doc.
        mutablebson::Document& doc = _preparedState->doc;
        mutablebson::Element current = doc.root().leftChild();
        while (current.ok()) {
            mutablebson::Element toRemove = current;
            current = current.rightSibling();
            Status status = toRemove.remove();
            if (!status.isOK()) {
                return status;
            }
        }

        // Insert the provided contents instead.
        BSONObjIterator it(_val);
        while (it.more()) {
            BSONElement elem = it.next();
            Status status = doc.root().appendElement(elem);
            if (!status.isOK()) {
                return status;
            }
        }

        return Status::OK();
    }

    Status ModifierObjectReplace::log(mutablebson::Element logRoot) const {

        // We'd like to create an entry such as {<object replacement>} under 'logRoot'.
        mutablebson::Document& doc = logRoot.getDocument();
        BSONObjIterator it(_val);
        while (it.more()) {
            BSONElement elem = it.next();
            Status status = doc.root().appendElement(elem);
            if (!status.isOK()) {
                return status;
            }
        }

        return Status::OK();
    }

} // namespace mongo
