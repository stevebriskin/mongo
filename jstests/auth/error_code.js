var conn = MongoRunner.runMongod({ auth : "", nojournal : "", port : 31001});

adminDb = conn.getDB('admin');
adminDb.addUser({user: 'admin', pwd: 'password', roles: jsTest.adminUserRoles});

assert( adminDb.auth('admin', 'password'), 'User should exist');
assert( !adminDb.auth('admin', 'xyz'), 'User does not exist');

//Test that bad auth is expected
nonce = adminDb.runCommand( {'getnonce' : 1} );
authres1 = adminDb.runCommand( { 'authenticate' : 1, 'user' : 'admin',
				 'nonce' : nonce.nonce, 'key' : 'b' } );
assert.eq(18, authres1.code, "Expected bad auth error code");

authres2 = adminDb.runCommand( { 'authenticate' : 1, 'user' : 'admin', 'key' : 'b' } );
assert.eq(17, authres2.code, "Expected bad command error code");

