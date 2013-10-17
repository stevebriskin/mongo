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

#include "mongo/platform/basic.h"

#include "mongo/db/auth/authorization_manager.h"

#include <boost/thread/mutex.hpp>
#include <memory>
#include <string>
#include <vector>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/bson/mutable/document.h"
#include "mongo/bson/mutable/element.h"
#include "mongo/db/auth/action_set.h"
#include "mongo/db/auth/authz_documents_update_guard.h"
#include "mongo/db/auth/authz_manager_external_state.h"
#include "mongo/db/auth/privilege.h"
#include "mongo/db/auth/role_graph.h"
#include "mongo/db/auth/user.h"
#include "mongo/db/auth/user_document_parser.h"
#include "mongo/db/auth/user_name.h"
#include "mongo/db/auth/user_name_hash.h"
#include "mongo/db/jsobj.h"
#include "mongo/platform/compiler.h"
#include "mongo/platform/unordered_map.h"
#include "mongo/util/log.h"
#include "mongo/util/map_util.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    AuthInfo internalSecurity;

    MONGO_INITIALIZER_WITH_PREREQUISITES(SetupInternalSecurityUser, MONGO_NO_PREREQUISITES)(
            InitializerContext* context) {

        User* user = new User(UserName("__system", "local"));

        user->incrementRefCount(); // Pin this user so the ref count never drops below 1.
        ActionSet allActions;
        allActions.addAllActions();
        PrivilegeVector privileges;
        RoleGraph::generateUniversalPrivileges(&privileges);
        user->addPrivileges(privileges);
        internalSecurity.user = user;

        return Status::OK();
    }

    const std::string AuthorizationManager::USER_NAME_FIELD_NAME = "user";
    const std::string AuthorizationManager::USER_SOURCE_FIELD_NAME = "db";
    const std::string AuthorizationManager::ROLE_NAME_FIELD_NAME = "role";
    const std::string AuthorizationManager::ROLE_SOURCE_FIELD_NAME = "db";
    const std::string AuthorizationManager::PASSWORD_FIELD_NAME = "pwd";
    const std::string AuthorizationManager::V1_USER_NAME_FIELD_NAME = "user";
    const std::string AuthorizationManager::V1_USER_SOURCE_FIELD_NAME = "userSource";

    const NamespaceString AuthorizationManager::adminCommandNamespace("admin.$cmd");
    const NamespaceString AuthorizationManager::rolesCollectionNamespace("admin.system.roles");
    const NamespaceString AuthorizationManager::usersCollectionNamespace("admin.system.users");
    const NamespaceString AuthorizationManager::versionCollectionNamespace("admin.system.version");


    bool AuthorizationManager::_doesSupportOldStylePrivileges = true;

    /**
     * Guard object for synchronizing accesses to the user cache.  This guard allows one thread to
     * access the cache at a time, and provides an exception-safe mechanism for a thread to release
     * the cache mutex while performing network or disk operations while allowing other readers
     * to proceed.
     *
     * There are two ways to use this guard.  One may simply instantiate the guard like a
     * std::lock_guard, and perform reads or writes of the cache.
     *
     * Alternatively, one may instantiate the guard, examine the cache, and then enter into an
     * update mode by first wait()ing until otherUpdateInFetchPhase() is false, and then
     * calling beginFetchPhase().  At this point, other threads may acquire the guard in the simple
     * manner and do reads, but other threads may not enter into a fetch phase.  During the fetch
     * phase, the thread should perform required network or disk activity to determine what update
     * it will make to the cache.  Then, it should call endFetchPhase(), to reacquire the user cache
     * mutex.  At that point, the thread can make its modifications to the cache and let the guard
     * go out of scope.
     *
     * All updates by guards using a fetch-phase are totally ordered with respect to one another,
     * and all guards using no fetch phase are totally ordered with respect to one another, but
     * there is not a total ordering among all guard objects.
     */
    class AuthorizationManager::CacheGuard {
        MONGO_DISALLOW_COPYING(CacheGuard);
    public:
        enum FetchSynchronization {
            fetchSynchronizationAutomatic,
            fetchSynchronizationManual
        };

        /**
         * Constructs a cache guard, locking the mutex that synchronizes user cache accesses.
         */
        CacheGuard(AuthorizationManager* authzManager,
                   const FetchSynchronization sync = fetchSynchronizationAutomatic) :
            _isThisGuardInFetchPhase(false),
            _authzManager(authzManager),
            _lock(authzManager->_userCacheMutex) {

            if (fetchSynchronizationAutomatic == sync) {
                synchronizeWithFetchPhase();
            }
        }

        /**
         * Releases the mutex that synchronizes user cache access, if held, and notifies
         * any threads waiting for their own opportunity to update the user cache.
         */
        ~CacheGuard() {
            if (!_lock.owns_lock()) {
                _lock.lock();
            }
            if (_isThisGuardInFetchPhase) {
                fassert(17190, _authzManager->_isFetchPhaseBusy);
                _authzManager->_isFetchPhaseBusy = false;
                _authzManager->_fetchPhaseIsReady.notify_all();
            }
        }

        bool otherUpdateInFetchPhase() { return _authzManager->_isFetchPhaseBusy; }

        void wait() {
            _authzManager->_fetchPhaseIsReady.wait(_lock);
        }

        void beginFetchPhase() {
            fassert(17191, !_authzManager->_isFetchPhaseBusy);
            _isThisGuardInFetchPhase = true;
            _authzManager->_isFetchPhaseBusy = true;
            _lock.unlock();
        }

        void endFetchPhase() {
            _lock.lock();
        }

    private:
        void synchronizeWithFetchPhase() {
            while (otherUpdateInFetchPhase())
                wait();
            fassert(17192, !_authzManager->_isFetchPhaseBusy);
            _isThisGuardInFetchPhase = true;
            _authzManager->_isFetchPhaseBusy = true;
        }

        bool _isThisGuardInFetchPhase;
        AuthorizationManager* _authzManager;
        boost::unique_lock<boost::mutex> _lock;
    };

    AuthorizationManager::AuthorizationManager(AuthzManagerExternalState* externalState) :
        _authEnabled(false), _externalState(externalState), _isFetchPhaseBusy(false) {

        setAuthorizationVersion(2);
    }

    AuthorizationManager::~AuthorizationManager() {
        for (unordered_map<UserName, User*>::iterator it = _userCache.begin();
                it != _userCache.end(); ++it) {
            if (it->second != internalSecurity.user) {
                // The internal user should never be deleted.
                delete it->second ;
            }
        }
    }

    Status AuthorizationManager::setAuthorizationVersion(int version) {
        CacheGuard guard(this);

        if (version != 1 && version != 2) {
            return Status(ErrorCodes::UnsupportedFormat,
                          mongoutils::str::stream() <<
                                  "Unrecognized authorization format version: " <<
                                  version);
        }

        _version = version;
        return Status::OK();
    }

    int AuthorizationManager::getAuthorizationVersion() {
        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        return _getVersion_inlock();
    }

    void AuthorizationManager::setSupportOldStylePrivilegeDocuments(bool enabled) {
        _doesSupportOldStylePrivileges = enabled;
    }

    bool AuthorizationManager::getSupportOldStylePrivilegeDocuments() {
        return _doesSupportOldStylePrivileges;
    }

    void AuthorizationManager::setAuthEnabled(bool enabled) {
        _authEnabled = enabled;
    }

    bool AuthorizationManager::isAuthEnabled() const {
        return _authEnabled;
    }

    bool AuthorizationManager::hasAnyPrivilegeDocuments() const {
        return _externalState->hasAnyPrivilegeDocuments();
    }

    Status AuthorizationManager::insertPrivilegeDocument(const std::string& dbname,
                                                         const BSONObj& userObj,
                                                         const BSONObj& writeConcern) const {
        return _externalState->insertPrivilegeDocument(dbname, userObj, writeConcern);
    }

    Status AuthorizationManager::updatePrivilegeDocument(const UserName& user,
                                                         const BSONObj& updateObj,
                                                         const BSONObj& writeConcern) const {
        return _externalState->updatePrivilegeDocument(user, updateObj, writeConcern);
    }

    Status AuthorizationManager::removePrivilegeDocuments(const BSONObj& query,
                                                          const BSONObj& writeConcern,
                                                          int* numRemoved) const {
        return _externalState->removePrivilegeDocuments(query, writeConcern, numRemoved);
    }

    Status AuthorizationManager::removeRoleDocuments(const BSONObj& query,
                                                     const BSONObj& writeConcern,
                                                     int* numRemoved) const {
        Status status = _externalState->remove(rolesCollectionNamespace,
                                               query,
                                               writeConcern,
                                               numRemoved);
        if (status.code() == ErrorCodes::UnknownError) {
            return Status(ErrorCodes::RoleModificationFailed, status.reason());
        }
        return status;
    }

    Status AuthorizationManager::insertRoleDocument(const BSONObj& roleObj,
                                                    const BSONObj& writeConcern) const {
        Status status = _externalState->insert(rolesCollectionNamespace,
                                               roleObj,
                                               writeConcern);
        if (status.isOK()) {
            return status;
        }
        if (status.code() == ErrorCodes::DuplicateKey) {
            std::string name = roleObj[AuthorizationManager::ROLE_NAME_FIELD_NAME].String();
            std::string source = roleObj[AuthorizationManager::ROLE_SOURCE_FIELD_NAME].String();
            return Status(ErrorCodes::DuplicateKey,
                          mongoutils::str::stream() << "Role \"" << name << "@" << source <<
                                  "\" already exists");
        }
        if (status.code() == ErrorCodes::UnknownError) {
            return Status(ErrorCodes::RoleModificationFailed, status.reason());
        }
        return status;
    }

    Status AuthorizationManager::updateRoleDocument(const RoleName& role,
                                                    const BSONObj& updateObj,
                                                    const BSONObj& writeConcern) const {
        Status status = _externalState->updateOne(
                rolesCollectionNamespace,
                BSON(AuthorizationManager::ROLE_NAME_FIELD_NAME << role.getRole() <<
                     AuthorizationManager::ROLE_SOURCE_FIELD_NAME << role.getDB()),
                updateObj,
                false,
                writeConcern);
        if (status.isOK()) {
            return status;
        }
        if (status.code() == ErrorCodes::NoMatchingDocument) {
            return Status(ErrorCodes::RoleNotFound,
                          mongoutils::str::stream() << "Role " << role.getFullName() <<
                                  " not found");
        }
        if (status.code() == ErrorCodes::UnknownError) {
            return Status(ErrorCodes::RoleModificationFailed, status.reason());
        }
        return status;
    }

    Status AuthorizationManager::queryAuthzDocument(
            const NamespaceString& collectionName,
            const BSONObj& query,
            const BSONObj& projection,
            const boost::function<void(const BSONObj&)>& resultProcessor) {
        return _externalState->query(collectionName, query, projection, resultProcessor);
    }

    Status AuthorizationManager::updateAuthzDocuments(const NamespaceString& collectionName,
                                                      const BSONObj& query,
                                                      const BSONObj& updatePattern,
                                                      bool upsert,
                                                      bool multi,
                                                      const BSONObj& writeConcern,
                                                      int* numUpdated) const {
        return _externalState->update(collectionName,
                                      query,
                                      updatePattern,
                                      upsert,
                                      multi,
                                      writeConcern,
                                      numUpdated);
    }

    Status AuthorizationManager::getBSONForPrivileges(const PrivilegeVector& privileges,
                                                      mutablebson::Element resultArray) {
        for (PrivilegeVector::const_iterator it = privileges.begin();
                it != privileges.end(); ++it) {
            std::string errmsg;
            ParsedPrivilege privilege;
            if (!ParsedPrivilege::privilegeToParsedPrivilege(*it, &privilege, &errmsg)) {
                return Status(ErrorCodes::BadValue, errmsg);
            }
            resultArray.appendObject("privileges", privilege.toBSON());
        }
        return Status::OK();
    }

    Status AuthorizationManager::getBSONForRole(RoleGraph* graph,
                                                const RoleName& roleName,
                                                mutablebson::Element result) {
        if (!graph->roleExists(roleName)) {
            return Status(ErrorCodes::RoleNotFound,
                          mongoutils::str::stream() << roleName.getFullName() <<
                                  "does not name an existing role");
        }
        std::string id = mongoutils::str::stream() << roleName.getDB() << "." << roleName.getRole();
        result.appendString("_id", id);
        result.appendString(ROLE_NAME_FIELD_NAME, roleName.getRole());
        result.appendString(ROLE_SOURCE_FIELD_NAME, roleName.getDB());

        // Build privileges array
        mutablebson::Element privilegesArrayElement =
                result.getDocument().makeElementArray("privileges");
        result.pushBack(privilegesArrayElement);
        const PrivilegeVector& privileges = graph->getDirectPrivileges(roleName);
        Status status = getBSONForPrivileges(privileges, privilegesArrayElement);
        if (!status.isOK()) {
            return status;
        }

        // Build roles array
        mutablebson::Element rolesArrayElement = result.getDocument().makeElementArray("roles");
        result.pushBack(rolesArrayElement);
        for (RoleNameIterator roles = graph->getDirectSubordinates(roleName);
             roles.more();
             roles.next()) {

            const RoleName& subRole = roles.get();
            mutablebson::Element roleObj = result.getDocument().makeElementObject("");
            roleObj.appendString(ROLE_NAME_FIELD_NAME, subRole.getRole());
            roleObj.appendString(ROLE_SOURCE_FIELD_NAME, subRole.getDB());
            rolesArrayElement.pushBack(roleObj);
        }

        return Status::OK();
    }

    static void _initializeUserPrivilegesFromRolesV1(User* user) {
        const User::RoleDataMap& roles = user->getRoles();
        PrivilegeVector privileges;
        for (User::RoleDataMap::const_iterator it = roles.begin(); it != roles.end(); ++it) {
            const User::RoleData& role= it->second;
            if (role.hasRole) {
                RoleGraph::addPrivilegesForBuiltinRole(role.name, &privileges);
            }
        }
        user->addPrivileges(privileges);
    }

    Status AuthorizationManager::_initializeUserFromPrivilegeDocument(
            User* user, const BSONObj& privDoc) {
        V2UserDocumentParser parser;
        std::string userName = parser.extractUserNameFromUserDocument(privDoc);
        if (userName != user->getName().getUser()) {
            return Status(ErrorCodes::BadValue,
                          mongoutils::str::stream() << "User name from privilege document \""
                                  << userName
                                  << "\" doesn't match name of provided User \""
                                  << user->getName().getUser()
                                  << "\"",
                          0);
        }

        Status status = parser.initializeUserCredentialsFromUserDocument(user, privDoc);
        if (!status.isOK()) {
            return status;
        }
        status = parser.initializeUserRolesFromUserDocument(privDoc, user);
        if (!status.isOK()) {
            return status;
        }
        status = parser.initializeUserPrivilegesFromUserDocument(privDoc, user);
        return Status::OK();
    }

    Status AuthorizationManager::getUserDescription(const UserName& userName, BSONObj* result) {
        return _externalState->getUserDescription(userName, result);
    }

    Status AuthorizationManager::getRoleDescription(const RoleName& roleName, BSONObj* result) {
        return _externalState->getRoleDescription(roleName, result);
    }

    Status AuthorizationManager::acquireUser(const UserName& userName, User** acquiredUser) {
        unordered_map<UserName, User*>::iterator it;

        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        while ((_userCache.end() == (it = _userCache.find(userName))) &&
               guard.otherUpdateInFetchPhase()) {

            guard.wait();
        }

        if (it != _userCache.end()) {
            fassert(16914, it->second);
            fassert(17003, it->second->isValid());
            fassert(17008, it->second->getRefCount() > 0);
            it->second->incrementRefCount();
            *acquiredUser = it->second;
            return Status::OK();
        }

        if (_getVersion_inlock() != 2) {
            return Status(ErrorCodes::UserNotFound, mongoutils::str::stream() <<
                          "User " << userName.getFullName() << " not found.");
        }

        guard.beginFetchPhase();
        BSONObj userObj;
        Status status = getUserDescription(userName, &userObj);
        if (!status.isOK()) {
            return status;
        }

        // Put the new user into an auto_ptr temporarily in case there's an error while
        // initializing the user.
        auto_ptr<User> userHolder(new User(userName));
        User* user = userHolder.get();

        status = _initializeUserFromPrivilegeDocument(user, userObj);
        if (!status.isOK()) {
            return status;
        }

        guard.endFetchPhase();
        user->incrementRefCount();
        _userCache.insert(make_pair(userName, userHolder.release()));
        *acquiredUser = user;
        return Status::OK();
    }

    void AuthorizationManager::releaseUser(User* user) {
        if (user == internalSecurity.user) {
            return;
        }

        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        user->decrementRefCount();
        if (user->getRefCount() == 0) {
            // If it's been invalidated then it's not in the _userCache anymore.
            if (user->isValid()) {
                MONGO_COMPILER_VARIABLE_UNUSED bool erased = _userCache.erase(user->getName());
                dassert(erased);
            }
            delete user;
        }
    }

    void AuthorizationManager::invalidateUserByName(const UserName& userName) {
        CacheGuard guard(this);
        unordered_map<UserName, User*>::iterator it = _userCache.find(userName);
        if (it == _userCache.end()) {
            return;
        }

        User* user = it->second;
        _userCache.erase(it);
        user->invalidate();
    }

    void AuthorizationManager::invalidateUsersFromDB(const std::string& dbname) {
        CacheGuard guard(this);
        unordered_map<UserName, User*>::iterator it = _userCache.begin();
        while (it != _userCache.end()) {
            User* user = it->second;
            if (user->getName().getDB() == dbname) {
                _userCache.erase(it++);
                user->invalidate();
            } else {
                ++it;
            }
        }
    }


    void AuthorizationManager::addInternalUser(User* user) {
        CacheGuard guard(this);
        _userCache.insert(make_pair(user->getName(), user));
    }

    void AuthorizationManager::invalidateUserCache() {
        CacheGuard guard(this);
        _invalidateUserCache_inlock();
    }

    void AuthorizationManager::_invalidateUserCache_inlock() {
        for (unordered_map<UserName, User*>::iterator it = _userCache.begin();
                it != _userCache.end(); ++it) {
            if (it->second->getName() == internalSecurity.user->getName()) {
                // Don't invalidate the internal user
                continue;
            }
            it->second->invalidate();
            // // Need to decrement ref count and manually clean up User object to prevent memory leaks
            // // since we're pinning all User objects by incrementing their ref count when we
            // // initially populate the cache.
            // // TODO(spencer): remove this once we're not pinning User objects.
            // it->second->decrementRefCount();
            // if (it->second->getRefCount() == 0)
            //     delete it->second;
        }
        _userCache.clear();
        // Make sure the internal user stays in the cache.
        _userCache.insert(make_pair(internalSecurity.user->getName(), internalSecurity.user));
    }

    Status AuthorizationManager::initialize() {
        Status status = _externalState->initialize();
        if (!status.isOK())
            return status;

        if (isAuthEnabled() && getAuthorizationVersion() < 2) {
            // If we are not yet upgraded to the V2 authorization format, build up a read-only
            // view of the V1 style authorization data.
            return _initializeAllV1UserData();
        }

        return Status::OK();
    }

    Status AuthorizationManager::_initializeAllV1UserData() {
        CacheGuard guard(this);
        _invalidateUserCache_inlock();
        V1UserDocumentParser parser;

        try {
            std::vector<std::string> dbNames;
            Status status = _externalState->getAllDatabaseNames(&dbNames);
            if (!status.isOK()) {
                return status;
            }

            for (std::vector<std::string>::iterator dbIt = dbNames.begin();
                    dbIt != dbNames.end(); ++dbIt) {
                std::string dbname = *dbIt;
                std::vector<BSONObj> privDocs;
                Status status = _externalState->getAllV1PrivilegeDocsForDB(dbname, &privDocs);
                if (!status.isOK()) {
                    return status;
                }

                for (std::vector<BSONObj>::iterator docIt = privDocs.begin();
                        docIt != privDocs.end(); ++docIt) {
                    const BSONObj& privDoc = *docIt;

                    std::string source;
                    if (privDoc.hasField("userSource")) {
                        source = privDoc["userSource"].String();
                    } else {
                        source = dbname;
                    }
                    UserName userName(privDoc["user"].String(), source);
                    if (userName == internalSecurity.user->getName()) {
                        // Don't let clients override the internal user by creating a user with the
                        // same name.
                        continue;
                    }

                    User* user = mapFindWithDefault(_userCache, userName, static_cast<User*>(NULL));
                    if (!user) {
                        user = new User(userName);
                        // Make sure the user always has a refCount of at least 1 so it's
                        // effectively "pinned" and will never be removed from the _userCache
                        // unless the whole cache is invalidated.
                        user->incrementRefCount();
                        _userCache.insert(make_pair(userName, user));
                    }

                    if (source == dbname || source == "$external") {
                        status = parser.initializeUserCredentialsFromUserDocument(user,
                                                                                  privDoc);
                        if (!status.isOK()) {
                            return status;
                        }
                    }
                    status = parser.initializeUserRolesFromUserDocument(user, privDoc, dbname);
                    if (!status.isOK()) {
                        return status;
                    }
                    _initializeUserPrivilegesFromRolesV1(user);
                }
            }
        } catch (const DBException& e) {
            return e.toStatus();
        } catch (const std::exception& e) {
            return Status(ErrorCodes::InternalError, e.what());
        }

        return Status::OK();
    }

    bool AuthorizationManager::tryAcquireAuthzUpdateLock(const StringData& why) {
        return _externalState->tryAcquireAuthzUpdateLock(why);
    }

    void AuthorizationManager::releaseAuthzUpdateLock() {
        return _externalState->releaseAuthzUpdateLock();
    }

    namespace {
        BSONObj userAsV2PrivilegeDocument(const User& user) {
            BSONObjBuilder builder;

            const UserName& name = user.getName();
            builder.append(AuthorizationManager::USER_NAME_FIELD_NAME, name.getUser());
            builder.append(AuthorizationManager::USER_SOURCE_FIELD_NAME, name.getDB());

            const User::CredentialData& credentials = user.getCredentials();
            if (!credentials.isExternal) {
                BSONObjBuilder credentialsBuilder(builder.subobjStart("credentials"));
                credentialsBuilder.append("MONGODB-CR", credentials.password);
                credentialsBuilder.doneFast();
            }

            BSONArrayBuilder rolesArray(builder.subarrayStart("roles"));
            const User::RoleDataMap& roles = user.getRoles();
            for (User::RoleDataMap::const_iterator it = roles.begin(); it != roles.end(); ++it) {
                const User::RoleData& role = it->second;
                BSONObjBuilder roleBuilder(rolesArray.subobjStart());
                roleBuilder.append(AuthorizationManager::USER_NAME_FIELD_NAME, role.name.getRole());
                roleBuilder.append(AuthorizationManager::USER_SOURCE_FIELD_NAME, role.name.getDB());
                roleBuilder.appendBool("canDelegate", role.canDelegate);
                roleBuilder.appendBool("hasRole", role.hasRole);
                roleBuilder.doneFast();
            }
            rolesArray.doneFast();
            return builder.obj();
        }

        const NamespaceString newusersCollectionNamespace("admin._newusers");
        const NamespaceString backupUsersCollectionNamespace("admin.backup.users");
        const BSONObj versionDocumentQuery = BSON("_id" << 1);

        /**
         * Fetches the admin.system.version document and extracts the currentVersion field's
         * value, supposing it is an integer, and writes it to outVersion.
         */
        Status readAuthzVersion(AuthzManagerExternalState* externalState, int* outVersion) {
            BSONObj versionDoc;
            Status status = externalState->findOne(
                    AuthorizationManager::versionCollectionNamespace,
                    versionDocumentQuery,
                    &versionDoc);
            if (!status.isOK() && ErrorCodes::NoMatchingDocument != status) {
                return status;
            }
            BSONElement currentVersionElement = versionDoc["currentVersion"];
            if (!versionDoc.isEmpty() && !currentVersionElement.isNumber()) {
                return Status(ErrorCodes::TypeMismatch,
                              "Field 'currentVersion' in admin.system.version must be a number.");
            }
            *outVersion = currentVersionElement.numberInt();
            return Status::OK();
        }
    }  // namespace

    Status AuthorizationManager::upgradeAuthCollections() {
        AuthzDocumentsUpdateGuard lkUpgrade(this);
        if (!lkUpgrade.tryLock("Upgrade authorization data")) {
            return Status(ErrorCodes::LockBusy, "Could not lock auth data upgrade process lock.");
        }
        CacheGuard guard(this);
        int durableVersion = 0;
        Status status = readAuthzVersion(_externalState.get(), &durableVersion);
        if (!status.isOK())
            return status;

        if (_version == 2) {
            switch (durableVersion) {
            case 0:
            case 1: {
                const char msg[] = "User data format version in memory and on disk inconsistent; "
                    "please restart this node.";
                error() << msg;
                return Status(ErrorCodes::UserDataInconsistent, msg);
            }
            case 2:
                return Status::OK();
            default:
                return Status(ErrorCodes::BadValue,
                              mongoutils::str::stream() <<
                              "Cannot upgrade admin.system.version to 2 from " <<
                              durableVersion);
            }
        }
        fassert(17113, _version == 1);
        switch (durableVersion) {
        case 0:
        case 1:
            break;
        case 2: {
            const char msg[] = "User data format version in memory and on disk inconsistent; "
                "please restart this node.";
            error() << msg;
            return Status(ErrorCodes::UserDataInconsistent, msg);
        }
        default:
                return Status(ErrorCodes::BadValue,
                              mongoutils::str::stream() <<
                              "Cannot upgrade admin.system.version from 2 to " <<
                              durableVersion);
        }

        BSONObj writeConcern;
        // Upgrade from v1 to v2.
        status = _externalState->copyCollection(usersCollectionNamespace,
                                                backupUsersCollectionNamespace,
                                                writeConcern);
        if (!status.isOK())
            return status;
        status = _externalState->dropCollection(newusersCollectionNamespace, writeConcern);
        if (!status.isOK())
            return status;
        status = _externalState->createIndex(
                newusersCollectionNamespace,
                BSON(USER_NAME_FIELD_NAME << 1 << USER_SOURCE_FIELD_NAME << 1),
                true, // unique
                writeConcern
                );
        if (!status.isOK())
            return status;

        for (unordered_map<UserName, User*>::const_iterator iter = _userCache.begin();
             iter != _userCache.end(); ++iter) {

            // Do not create a user document for the internal user.
            if (iter->second == internalSecurity.user)
                continue;

            status = _externalState->insert(
                    newusersCollectionNamespace, userAsV2PrivilegeDocument(*iter->second),
                    writeConcern);
            if (!status.isOK())
                return status;
        }
        status = _externalState->renameCollection(newusersCollectionNamespace,
                                                  usersCollectionNamespace,
                                                  writeConcern);
        if (!status.isOK())
            return status;
        status = _externalState->updateOne(
                versionCollectionNamespace,
                versionDocumentQuery,
                BSON("$set" << BSON("currentVersion" << 2)),
                true,
                writeConcern);
        if (!status.isOK())
            return status;
        _version = 2;
        return status;
    }

    void AuthorizationManager::logOp(
            const char* op,
            const char* ns,
            const BSONObj& o,
            BSONObj* o2,
            bool* b,
            bool fromMigrateUnused,
            const BSONObj* fullObjUnused) {

        _externalState->logOp(op, ns, o, o2, b, fromMigrateUnused, fullObjUnused);
        if (ns == rolesCollectionNamespace.ns() ||
            ns == adminCommandNamespace.ns() ||
            ns == usersCollectionNamespace.ns()) {
            CacheGuard guard(this);
            if (_getVersion_inlock() == 2) {
                _invalidateUserCache_inlock();
            }
        }
    }

} // namespace mongo
