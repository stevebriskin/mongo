/*    Copyright 2012 10gen Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 * Unit tests of the AuthorizationManager type.
 */

#include "mongo/base/status.h"
#include "mongo/db/auth/authz_session_external_state_mock.h"
#include "mongo/db/auth/authz_manager_external_state_mock.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/namespacestring.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/map_util.h"

#define ASSERT_NULL(EXPR) ASSERT_FALSE(EXPR)
#define ASSERT_NON_NULL(EXPR) ASSERT_TRUE(EXPR)

namespace mongo {
namespace {

    class AuthorizationManagerTest : public ::mongo::unittest::Test {
    public:
        scoped_ptr<AuthorizationManager> authzManager;
        void setUp() {
            authzManager.reset(new AuthorizationManager(new AuthzManagerExternalStateMock()));
        }
    };

    TEST_F(AuthorizationManagerTest, GetPrivilegesFromPrivilegeDocumentCompatible) {
        UserName user("Spencer", "test");
        BSONObj invalid;
        BSONObj readWrite = BSON("user" << "Spencer" << "pwd" << "passwordHash");
        BSONObj readOnly = BSON("user" << "Spencer" << "pwd" << "passwordHash" <<
                                "readOnly" << true);

        PrivilegeSet privilegeSet;
        ASSERT_EQUALS(ErrorCodes::UnsupportedFormat,
                      authzManager->buildPrivilegeSet("test",
                                                      user,
                                                      invalid,
                                                      &privilegeSet).code());

        ASSERT_OK(authzManager->buildPrivilegeSet("test",
                                                  user,
                                                  readOnly,
                                                  &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::insert)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));

        ASSERT_OK(authzManager->buildPrivilegeSet("test",
                                                  user,
                                                  readWrite,
                                                  &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::insert)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::compact)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::shutdown)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::addShard)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("*", ActionType::find)));

        ASSERT_OK(authzManager->buildPrivilegeSet("admin",
                                                  user,
                                                  readOnly,
                                                  &privilegeSet));
        // Should grant privileges on *.
        ASSERT(privilegeSet.hasPrivilege(Privilege("*", ActionType::find)));

        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::insert)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("*", ActionType::insert)));

        ASSERT_OK(authzManager->buildPrivilegeSet("admin",
                                                  user,
                                                  readWrite,
                                                  &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("*", ActionType::insert)));
    }

    class PrivilegeDocumentParsing : public AuthorizationManagerTest {
    public:
        PrivilegeDocumentParsing() : user("spencer", "test") {}

        UserName user;
        PrivilegeSet privilegeSet;
    };

    TEST_F(PrivilegeDocumentParsing, VerifyRolesFieldMustBeAnArray) {
        ASSERT_NOT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << "read"),
                              &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyInvalidRoleGrantsNoPrivileges) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("frim")),
                              &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyInvalidRoleStillAllowsOtherRoles) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "frim")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantClusterAdminRoleFromNonAdminDatabase) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "clusterAdmin")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::shutdown)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::dropDatabase)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantClusterReadFromNonAdminDatabase) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "readAnyDatabase")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantClusterReadWriteFromNonAdminDatabase) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "readWriteAnyDatabase")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::insert)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::insert)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantClusterUserAdminFromNonAdminDatabase) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "userAdminAnyDatabase")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::userAdmin)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantClusterDBAdminFromNonAdminDatabase) {
        ASSERT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read" << "dbAdminAnyDatabase")),
                              &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::clean)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::clean)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyOtherDBRolesMustBeAnObjectOfArraysOfStrings) {
        ASSERT_NOT_OK(authzManager->buildPrivilegeSet(
                              "admin",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read") <<
                                   "otherDBRoles" << BSON_ARRAY("read")),
                              &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));

        ASSERT_NOT_OK(authzManager->buildPrivilegeSet(
                              "admin",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read") <<
                                   "otherDBRoles" << BSON("test2" << "read")),
                              &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, VerifyCannotGrantPrivilegesOnOtherDatabasesNormally) {
        // Cannot grant privileges on other databases, except from admin database.
        ASSERT_NOT_OK(authzManager->buildPrivilegeSet(
                              "test",
                              user,
                              BSON("user" << "spencer" << "pwd" << "" <<
                                   "roles" << BSON_ARRAY("read") <<
                                   "otherDBRoles" << BSON("test2" << BSON_ARRAY("read"))),
                              &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, SuccessfulSimpleReadGrant) {
        // Grant read on test.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "test",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" << "roles" << BSON_ARRAY("read")),
                          &privilegeSet));

        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));
    }

    TEST_F(PrivilegeDocumentParsing, SuccessfulSimpleUserAdminTest) {
        // Grant userAdmin on "test" database.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "test",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSON_ARRAY("userAdmin")),
                          &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::userAdmin)));
    }

    TEST_F(PrivilegeDocumentParsing, GrantUserAdminOnAdmin) {
        // Grant userAdmin on admin.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSON_ARRAY("userAdmin")),
                          &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::userAdmin)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("admin", ActionType::userAdmin)));
    }

    TEST_F(PrivilegeDocumentParsing, GrantUserAdminOnTestViaAdmin) {
        // Grant userAdmin on test via admin.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSONArrayBuilder().arr() <<
                               "otherDBRoles" << BSON("test" << BSON_ARRAY("userAdmin"))),
                          &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::userAdmin)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::userAdmin)));
    }

    TEST_F(PrivilegeDocumentParsing, SuccessfulClusterAdminTest) {
        // Grant userAdminAnyDatabase.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSON_ARRAY("userAdminAnyDatabase")),
                          &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::userAdmin)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test2", ActionType::userAdmin)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("admin", ActionType::userAdmin)));
    }


    TEST_F(PrivilegeDocumentParsing, GrantClusterReadWrite) {
        // Grant readWrite on everything via the admin database.
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSON_ARRAY("readWriteAnyDatabase")),
                          &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::insert)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test2", ActionType::insert)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("admin", ActionType::insert)));
    }

    TEST_F(PrivilegeDocumentParsing, ProhibitGrantOnWildcard) {
        // Cannot grant readWrite to everythign using "otherDBRoles".
        ASSERT_NOT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSONArrayBuilder().arr() <<
                               "otherDBRoles" << BSON("*" << BSON_ARRAY("readWrite"))),
                          &privilegeSet));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::find)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test", ActionType::insert)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("test2", ActionType::insert)));
        ASSERT(!privilegeSet.hasPrivilege(Privilege("admin", ActionType::insert)));
    }

    TEST_F(PrivilegeDocumentParsing, GrantClusterAdmin) {
        // Grant cluster admin
        ASSERT_OK(authzManager->buildPrivilegeSet(
                          "admin",
                          user,
                          BSON("user" << "spencer" << "pwd" << "" <<
                               "roles" << BSON_ARRAY("clusterAdmin")),
                          &privilegeSet));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test", ActionType::dropDatabase)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("test2", ActionType::dropDatabase)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("admin", ActionType::dropDatabase)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("$SERVER", ActionType::shutdown)));
        ASSERT(privilegeSet.hasPrivilege(Privilege("$CLUSTER", ActionType::moveChunk)));
    }

    TEST_F(AuthorizationManagerTest, GetPrivilegesFromPrivilegeDocumentInvalid) {
        BSONObj oldAndNewMixed = BSON("user" << "spencer" <<
                                      "pwd" << "passwordHash" <<
                                      "readOnly" << false <<
                                      "roles" << BSON_ARRAY("write" << "userAdmin"));

        UserName user("spencer", "anydb");
        PrivilegeSet result;
        ASSERT_NOT_OK(authzManager->buildPrivilegeSet("anydb", user, oldAndNewMixed, &result));
    }

    TEST_F(AuthorizationManagerTest, DocumentValidationCompatibility) {

        // Good documents, with and without "readOnly" fields.
        ASSERT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << "a")));
        ASSERT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << "a" << "readOnly" << 1)));
        ASSERT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << "a" << "readOnly" << false)));
        ASSERT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << "a" << "readOnly" << "yes")));

        // Must have a "pwd" field.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy")));

        // "pwd" field must be a string.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << 100)));

        // "pwd" field string must not be empty.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "andy" << "pwd" << "")));

        // Must have a "user" field.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("pwd" << "a")));

        // "user" field must be a string.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << 100 << "pwd" << "a")));

        // "user" field string must not be empty.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument(
                "test", BSON("user" << "" << "pwd" << "a")));
    }


    class CompatibilityModeDisabler {
    public:
        CompatibilityModeDisabler() {
            AuthorizationManager::setSupportOldStylePrivilegeDocuments(false);
        }
        ~CompatibilityModeDisabler() {
            AuthorizationManager::setSupportOldStylePrivilegeDocuments(true);
        }
    };

    TEST_F(AuthorizationManagerTest, DisableCompatibilityMode) {
        CompatibilityModeDisabler disabler;

        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a")));
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" << "readOnly" << 1)));
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" << "readOnly" << false)));
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" << "readOnly" << "yes")));

        ASSERT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" <<
                     "roles" << BSON_ARRAY("dbAdmin" << "read"))));
    }

    TEST_F(AuthorizationManagerTest, DocumentValidationExtended) {
        // Document describing new-style user on "test".
        ASSERT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" << "roles" << BSON_ARRAY("read"))));

        // Document giving roles on "test" to a user from "test2".
        ASSERT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "userSource" << "test2" <<
                     "roles" << BSON_ARRAY("read"))));

        // Cannot have "userSource" field value == dbname.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "userSource" << "test" <<
                     "roles" << BSON_ARRAY("read"))));

        // Cannot have both "userSource" and "pwd"
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "userSource" << "test2" << "pwd" << "a" <<
                     "roles" << BSON_ARRAY("read"))));

        // Cannot have an otherDBRoles field except in the admin database.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                            BSON("user" << "andy" << "userSource" << "test2" <<
                                 "roles" << BSON_ARRAY("read") <<
                                 "otherDBRoles" << BSON("test2" << BSON_ARRAY("readWrite")))));

        ASSERT_OK(authzManager->checkValidPrivilegeDocument("admin",
                        BSON("user" << "andy" << "userSource" << "test2" <<
                             "roles" << BSON_ARRAY("read") <<
                             "otherDBRoles" << BSON("test2" << BSON_ARRAY("readWrite")))));

        // Must have "roles" to have "otherDBRoles".
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("admin",
                            BSON("user" << "andy" << "pwd" << "a" <<
                                 "otherDBRoles" << BSON("test2" << BSON_ARRAY("readWrite")))));

        ASSERT_OK(authzManager->checkValidPrivilegeDocument("admin",
                        BSON("user" << "andy" << "pwd" << "a" <<
                             "roles" << BSONArrayBuilder().arr() <<
                             "otherDBRoles" << BSON("test2" << BSON_ARRAY("readWrite")))));

        // "otherDBRoles" may be empty.
        ASSERT_OK(authzManager->checkValidPrivilegeDocument("admin",
                        BSON("user" << "andy" << "pwd" << "a" <<
                             "roles" << BSONArrayBuilder().arr() <<
                             "otherDBRoles" << BSONObjBuilder().obj())));

        // Cannot omit "roles" if "userSource" is present.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "userSource" << "test2")));

        // Cannot have both "roles" and "readOnly".
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" << "readOnly" << 1 <<
                     "roles" << BSON_ARRAY("read"))));

        // Roles must be strings, not empty.
        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" <<
                     "roles" << BSON_ARRAY("read" << ""))));

        ASSERT_NOT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" <<
                     "roles" << BSON_ARRAY(1 << "read"))));

        // Multiple roles OK.
        ASSERT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" <<
                     "roles" << BSON_ARRAY("dbAdmin" << "read"))));

        // Empty roles list OK.
        ASSERT_OK(authzManager->checkValidPrivilegeDocument("test",
                BSON("user" << "andy" << "pwd" << "a" <<
                     "roles" << BSONArrayBuilder().arr())));
    }

}  // namespace
}  // namespace mongo
