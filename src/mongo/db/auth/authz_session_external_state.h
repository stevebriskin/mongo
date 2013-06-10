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

#pragma once

#include <string>

#include "mongo/base/disallow_copying.h"
#include "mongo/base/status.h"
#include "mongo/client/dbclientinterface.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/user_name.h"

namespace mongo {

    class Principal;

    /**
     * Public interface for a class that encapsulates all the session information related to system
     * state not stored in AuthorizationSession.  This is primarily to make AuthorizationSession
     * easier to test as well as to allow different implementations in mongos and mongod.
     */
    class AuthzSessionExternalState {
        MONGO_DISALLOW_COPYING(AuthzSessionExternalState);

    public:

        virtual ~AuthzSessionExternalState();

        const AuthorizationManager& getAuthorizationManager() const;

        // Returns true if this connection should be treated as if it has full access to do
        // anything, regardless of the current auth state.  Currently the reasons why this could be
        // are that auth isn't enabled, the connection is from localhost and there are no admin
        // users, or the connection is a "god" connection.
        // NOTE: _checkShouldAllowLocalhost MUST be called at least once before any call to
        // shouldIgnoreAuthChecks or we could ignore auth checks incorrectly.
        virtual bool shouldIgnoreAuthChecks() const = 0;

        // Should be called at the beginning of every new request.  This performs the checks
        // necessary to determine if localhost connections should be given full access.
        virtual void startRequest() = 0;

        // Authorization event hooks

        // Handle any global state which needs to be updated when a new user has been authorized
        virtual void onAddAuthorizedPrincipal(Principal*) = 0;

        // Handle any global state which needs to be updated when a user logs out
        virtual void onLogoutDatabase(const std::string& dbname) = 0;

    protected:
        // This class should never be instantiated directly.
        AuthzSessionExternalState(AuthorizationManager* authzManager);

        AuthorizationManager* _authzManager;
    };

} // namespace mongo
