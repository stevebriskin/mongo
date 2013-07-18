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


#include "mongo/db/ops/modifier_add_to_set.h"

#include "mongo/base/string_data.h"
#include "mongo/bson/mutable/document.h"
#include "mongo/bson/mutable/mutable_bson_test_utils.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/json.h"
#include "mongo/platform/cstdint.h"
#include "mongo/unittest/unittest.h"

namespace {

    using mongo::BSONObj;
    using mongo::ModifierAddToSet;
    using mongo::ModifierInterface;
    using mongo::Status;
    using mongo::StringData;
    using mongo::fromjson;
    using mongo::mutablebson::Document;
    using mongo::mutablebson::Element;

    /** Helper to build and manipulate a $addToSet mod. */
    class Mod {
    public:
        Mod() : _mod() {}

        explicit Mod(BSONObj modObj)
            : _modObj(modObj)
            , _mod() {
            ASSERT_OK(_mod.init(_modObj["$addToSet"].embeddedObject().firstElement()));
        }

        Status prepare(Element root,
                       const StringData& matchedField,
                       ModifierInterface::ExecInfo* execInfo) {
            return _mod.prepare(root, matchedField, execInfo);
        }

        Status apply() const {
            return _mod.apply();
        }

        Status log(Element logRoot) const {
            return _mod.log(logRoot);
        }

        ModifierAddToSet& mod() {
            return _mod;
        }

    private:
        BSONObj _modObj;
        ModifierAddToSet _mod;
    };

    TEST(Init, FailToInitWithInvalidValue) {
        BSONObj modObj;
        ModifierAddToSet mod;

        modObj = fromjson("{ $addToSet : { a : { 'x.$.y' : 'bad' } } }");
        ASSERT_NOT_OK(mod.init(modObj["$addToSet"].embeddedObject().firstElement()));

        modObj = fromjson("{ $addToSet : { a : { $each : [ { 'x.$.y' : 'bad' } ] } } }");
        ASSERT_NOT_OK(mod.init(modObj["$addToSet"].embeddedObject().firstElement()));

        // An int is not valid after $each
        modObj = fromjson("{ $addToSet : { a : { $each : 0 } } }");
        ASSERT_NOT_OK(mod.init(modObj["$addToSet"].embeddedObject().firstElement()));

        // An object is not valid after $each
        modObj = fromjson("{ $addToSet : { a : { $each : { a : 1 } } } }");
        ASSERT_NOT_OK(mod.init(modObj["$addToSet"].embeddedObject().firstElement()));
    }

    TEST(Init, ParsesSimple) {
        Mod(fromjson("{ $addToSet : { a : 1 } }"));
        Mod(fromjson("{ $addToSet : { a : 'foo' } }"));
        Mod(fromjson("{ $addToSet : { a : {} } }"));
        Mod(fromjson("{ $addToSet : { a : { x : 1 } } }"));
        Mod(fromjson("{ $addToSet : { a : [] } }"));
        Mod(fromjson("{ $addToSet : { a : [1, 2] } } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : 1 } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : 'foo' } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : {} } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : { x : 1} } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : [] } }"));
        Mod(fromjson("{ $addToSet : { 'a.b' : [1, 2] } } }"));
    }

    TEST(Init, ParsesEach) {
        Mod(fromjson("{ $addToSet : { a : { $each : [] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ 1 ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ 1, 2 ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ 1, 2, 1 ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ {} ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ { x : 1 } ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ { x : 1 }, { y : 2 } ] } } }"));
        Mod(fromjson("{ $addToSet : { a : { $each : [ { x : 1 }, { y : 2 }, { x : 1 } ] } } }"));
    }

    TEST(SimpleMod, PrepareOKTargetNotFound) {
        Document doc(fromjson("{}"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);
    }

    TEST(SimpleMod, PrepareOKTargetFound) {
        Document doc(fromjson("{ a : [ 1 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_TRUE(execInfo.inPlace);
        ASSERT_TRUE(execInfo.noOp);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1 ] } }"), logDoc);
    }

    TEST(SimpleMod, PrepareInvalidTargetNumber) {
        Document doc(fromjson("{ a : 1 }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_NOT_OK(mod.prepare(doc.root(), "", &execInfo));
    }

    TEST(SimpleMod, PrepareInvalidTarget) {
        Document doc(fromjson("{ a : {} }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_NOT_OK(mod.prepare(doc.root(), "", &execInfo));
    }

    TEST(SimpleMod, ApplyAndLogEmptyDocument) {
        Document doc(fromjson("{}"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1 ] } }"), logDoc);
    }

    TEST(SimpleMod, ApplyAndLogEmptyArray) {
        Document doc(fromjson("{ a : [] }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1 ] } }"), logDoc);
    }

    TEST(SimpleEachMod, ApplyAndLogEmptyDocument) {
        Document doc(fromjson("{}"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [1, 2, 3] } } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1, 2, 3 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 2, 3 ] } }"), logDoc);
    }

    TEST(SimpleEachMod, ApplyAndLogEmptyArray) {
        Document doc(fromjson("{ a : [] }"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [1, 2, 3] } } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1, 2, 3 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 2, 3 ] } }"), logDoc);
    }

    TEST(SimpleMod, ApplyAndLogPopulatedArray) {
        Document doc(fromjson("{ a : [ 'x' ] }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 'x', 1 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 'x', 1 ] } }"), logDoc);
    }

    TEST(SimpleEachMod, ApplyAndLogPopulatedArray) {
        Document doc(fromjson("{ a : [ 'x' ] }"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [1, 2, 3] } } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.inPlace);
        ASSERT_FALSE(execInfo.noOp);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 'x', 1, 2, 3 ] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 'x', 1, 2, 3 ] } }"), logDoc);
    }

    TEST(NoOp, AddOneExistingIsNoOp) {
        Document doc(fromjson("{ a : [ 1, 2, 3 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : 1 } }"));
        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_TRUE(execInfo.noOp);
        ASSERT_TRUE(execInfo.inPlace);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 2, 3 ] } }"), logDoc);
    }

    TEST(NoOp, AddSeveralExistingIsNoOp) {
        Document doc(fromjson("{ a : [ 1, 2, 3 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [1, 2] } } }"));
        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_TRUE(execInfo.noOp);
        ASSERT_TRUE(execInfo.inPlace);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 2, 3 ] } }"), logDoc);
    }

    TEST(NoOp, AddAllExistingIsNoOp) {
        Document doc(fromjson("{ a : [ 1, 2, 3 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [1, 2, 3] } } }"));
        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_TRUE(execInfo.noOp);
        ASSERT_TRUE(execInfo.inPlace);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 2, 3 ] } }"), logDoc);
    }

    TEST(Deduplication, ExistingDuplicatesArePreserved) {
        Document doc(fromjson("{ a : [ 1, 1, 2, 1, 2, 2 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : 3 } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.noOp);
        ASSERT_FALSE(execInfo.inPlace);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1, 1, 2, 1, 2, 2, 3] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 1, 2, 1, 2, 2, 3] } }"), logDoc);
    }

    TEST(Deduplication, NewDuplicatesAreElided) {
        Document doc(fromjson("{ a : [ 1, 1, 2, 1, 2, 2 ] }"));
        Mod mod(fromjson("{ $addToSet : { a : { $each : [ 4, 1, 3, 2, 3, 1, 3, 3, 2, 4] } } }"));

        ModifierInterface::ExecInfo execInfo;
        ASSERT_OK(mod.prepare(doc.root(), "", &execInfo));
        ASSERT_EQUALS(execInfo.fieldRef[0]->dottedField(), "a");
        ASSERT_FALSE(execInfo.noOp);
        ASSERT_FALSE(execInfo.inPlace);

        ASSERT_OK(mod.apply());
        ASSERT_EQUALS(fromjson("{ a : [ 1, 1, 2, 1, 2, 2, 4, 3] }"), doc);

        Document logDoc;
        ASSERT_OK(mod.log(logDoc.root()));
        ASSERT_EQUALS(fromjson("{ $set : { a : [ 1, 1, 2, 1, 2, 2, 4, 3] } }"), logDoc);
    }

} // namespace
