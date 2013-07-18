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

#include "mongo/db/ops/update_driver.h"

#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/mutable/document.h"
#include "mongo/db/field_ref.h"
#include "mongo/db/field_ref_set.h"
#include "mongo/db/ops/modifier_object_replace.h"
#include "mongo/db/ops/modifier_table.h"
#include "mongo/util/embedded_builder.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    UpdateDriver::UpdateDriver(const Options& opts)
        : _multi(opts.multi)
        , _upsert(opts.upsert)
        , _logOp(opts.logOp) {
    }

    UpdateDriver::~UpdateDriver() {
        clear();
    }

    Status UpdateDriver::parse(const IndexPathSet& indexedFields, const BSONObj& updateExpr) {
        clear();

        _indexedFields = indexedFields;

        // Check if the update expression is a full object replacement.
        if (*updateExpr.firstElementFieldName() != '$') {
            if (_multi) {
                return Status(ErrorCodes::FailedToParse,
                              "multi update only works with $ operators");
            }

            // Modifiers expect BSONElements as input. But the input to object replace is, by
            // definition, an object. We wrap the 'updateExpr' as the mod is expecting. Note
            // that the wrapper is temporary so the object replace mod should make a copy of
            // the object.
            auto_ptr<ModifierObjectReplace> mod(new ModifierObjectReplace);
            BSONObj wrapper = BSON( "dummy" << updateExpr );
            Status status = mod->init(wrapper.firstElement());
            if (!status.isOK()) {
                return status;
            }

            _mods.push_back(mod.release());

            // Register the fact that this driver will only do full object replacements.
            _dollarModMode = false;

            return Status::OK();
        }

        // The update expression is made of mod operators, that is
        // { <$mod>: {...}, <$mod>: {...}, ...  }
        BSONObjIterator outerIter(updateExpr);
        while (outerIter.more()) {
            BSONElement outerModElem = outerIter.next();

            // Check whether this is a valid mod type.
            modifiertable::ModifierType modType = modifiertable::getType(outerModElem.fieldName());
            if (modType == modifiertable::MOD_UNKNOWN) {
                return Status(ErrorCodes::FailedToParse, "unknown modifier type");
            }

            // Check whether there is indeed a list of mods under this modifier.
            if (outerModElem.type() != Object) {
                return Status(ErrorCodes::FailedToParse, "List of mods must be an object");
            }

            // Check whether there are indeed mods under this modifier.
            if (outerModElem.embeddedObject().isEmpty()) {
                return Status(ErrorCodes::FailedToParse, "Empty expression after update $mod");
            }

            BSONObjIterator innerIter(outerModElem.embeddedObject());
            while (innerIter.more()) {
                BSONElement innerModElem = innerIter.next();

                auto_ptr<ModifierInterface> mod(modifiertable::makeUpdateMod(modType));
                dassert(mod.get());

                if (innerModElem.eoo()) {
                    return Status(ErrorCodes::FailedToParse,
                                  "empty entry in $mod expression list");
                }

                Status status = mod->init(innerModElem);
                if (!status.isOK()) {
                    return status;
                }

                _mods.push_back(mod.release());
            }
        }

        // Register the fact that there will be only $mod's in this driver -- no object
        // replacement.
        _dollarModMode = true;

        return Status::OK();
    }

    bool UpdateDriver::createFromQuery(const BSONObj query, BSONObj* newObj) const {
        // TODO
        // This moved from ModSet::createNewFromQuery
        // Check if it can be streamlined
        BSONObjBuilder bb;
        EmbeddedBuilder eb(&bb);
        BSONObjIteratorSorted i(query);
        while (i.more()) {
            BSONElement e = i.next();
            if (e.fieldName()[0] == '$') // for $atomic and anything else we add
                continue;

            if (e.type() == Object && e.embeddedObject().firstElementFieldName()[0] == '$') {
                // we have something like { x : { $gt : 5 } }
                // this can be a query piece
                // or can be a dbref or something

                int op = e.embeddedObject().firstElement().getGtLtOp();
                if (op > 0) {
                    // This means this is a $gt type filter, so don't make it part of the new
                    // object.
                    continue;
                }

                if (mongoutils::str::equals(e.embeddedObject().firstElement().fieldName(),
                                              "$not")) {
                    // A $not filter operator is not detected in getGtLtOp() and should not
                    // become part of the new object.
                    continue;
                }
            }

            eb.appendAs(e , e.fieldName());
        }
        eb.done();

        *newObj = bb.obj();
        return true;
    }

    Status UpdateDriver::update(const StringData& matchedField,
                                mutablebson::Document* doc,
                                BSONObj* logOpRec) {
        // TODO: assert that update() is called at most once in a !_multi case.

        FieldRefSet targetFields;
        _affectIndices = false;

        // Ask each of the mods to type check whether they can operate over the current document
        // and, if so, to change that document accordingly.
        for (vector<ModifierInterface*>::iterator it = _mods.begin(); it != _mods.end(); ++it) {
            ModifierInterface::ExecInfo execInfo;
            Status status = (*it)->prepare(doc->root(), matchedField, &execInfo);
            if (!status.isOK()) {
                return status;
            }

            // If a mod wants to be applied only if this is an upsert (or only if this is a
            // strict update), we should respect that. If a mod doesn't care, it would state
            // it is fine with ANY update context.
            bool validContext = false;
            if (execInfo.context == ModifierInterface::ExecInfo::ANY_CONTEXT ||
                execInfo.context == _context) {
                validContext = true;
            }

            // Gather which fields this mod is interested on and whether these fields were
            // "taken" by previous mods.  Note that not all mods are multi-field mods. When we
            // see an empty field, we may stop looking for others.
            for (int i = 0; i < ModifierInterface::ExecInfo::MAX_NUM_FIELDS; i++) {
                if (execInfo.fieldRef[i] == 0) {
                    break;
                }

                const FieldRef* other;
                if (!targetFields.insert(execInfo.fieldRef[i], &other)) {
                    return Status(ErrorCodes::ConflictingUpdateOperators,
                                  mongoutils::str::stream()
                                      << "Cannot update '" << other->dottedField()
                                      << "' and '" << execInfo.fieldRef[i]->dottedField()
                                      << "' at the same time");
                }

                // We start with the expectation that a mod will be in-place. But if the mod
                // touched an indexed field and the mod will indeed be executed -- that is, it
                // is not a no-op and it is in a valid context -- then we switch back to a
                // non-in-place mode.
                //
                // TODO: make mightBeIndexed and fieldRef like each other.
                if (!_affectIndices &&
                    !execInfo.noOp &&
                    validContext &&
                    _indexedFields.mightBeIndexed(execInfo.fieldRef[i]->dottedField())) {
                    _affectIndices = true;
                    doc->disableInPlaceUpdates();
                }
            }

            if (!execInfo.noOp && validContext) {
                Status status = (*it)->apply();
                if (!status.isOK()) {
                    return status;
                }
            }
        }

        // If we require a replication oplog entry for this update, go ahead and generate one.
        if (_logOp && logOpRec) {
            mutablebson::Document logDoc;
            for (vector<ModifierInterface*>::iterator it = _mods.begin(); it != _mods.end(); ++it) {
                Status status = (*it)->log(logDoc.root());
                if (!status.isOK()) {
                    return status;
                }
            }
            *logOpRec = logDoc.getObject();
        }

        return Status::OK();
    }

    size_t UpdateDriver::numMods() const {
        return _mods.size();
    }

    bool UpdateDriver::dollarModMode() const {
        return _dollarModMode;
    }

    bool UpdateDriver::modsAffectIndices() const {
        return _affectIndices;
    }

    bool UpdateDriver::multi() const {
        return _multi;
    }

    void UpdateDriver::setMulti(bool multi) {
        _multi = multi;
    }

    bool UpdateDriver::upsert() const {
        return _upsert;
    }

    void UpdateDriver::setUpsert(bool upsert) {
        _upsert = upsert;
    }

    bool UpdateDriver::logOp() const {
        return _logOp;
    }

    void UpdateDriver::setLogOp(bool logOp) {
        _logOp = logOp;
    }

    ModifierInterface::ExecInfo::UpdateContext UpdateDriver::context() const {
        return _context;
    }

    void UpdateDriver::setContext(ModifierInterface::ExecInfo::UpdateContext context) {
        _context = context;
    }

    void UpdateDriver::clear() {
        for (vector<ModifierInterface*>::iterator it = _mods.begin(); it != _mods.end(); ++it) {
            delete *it;
        }
        _indexedFields.clear();
        _dollarModMode = false;
    }

} // namespace mongo
