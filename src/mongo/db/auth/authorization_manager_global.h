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

#include "mongo/db/auth/authorization_manager.h"

namespace mongo {

    // Gets the singleton AuthorizationManager object for this server process.
    AuthorizationManager* getGlobalAuthorizationManager();

    // Sets the singleton AuthorizationManager object for this server process.
    // Must be called once at startup and then never again (unless clearGlobalAuthorizationManager
    // is called, at which point this can be called again, but should only happen in tests).
    void setGlobalAuthorizationManager(AuthorizationManager* authManager);

    // Sets the singleton AuthorizationManager object for this server process to NULL.
    // Should only be used in tests.
    void clearGlobalAuthorizationManager();

} // namespace mongo
