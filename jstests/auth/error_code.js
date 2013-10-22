var conn = MongoRunner.runMongod({ auth : '', 
				   nojournal : '', 
				   port : 31001,
				   setParameter: "authenticationMechanisms=MONGODB-CR,PLAIN,CRAM-MD5"});

adminDb = conn.getDB('admin');
adminDb.addUser({user: 'admin', pwd: 'password', roles: jsTest.adminUserRoles});

assert( adminDb.auth('admin', 'password'), 'User should exist');
assert( !adminDb.auth('admin', 'xyz'), 'User does not exist');

//auth throws an error with just a string, so checking the code has to be via a string check

var err1 = assert.throws(function(){adminDb._authOrThrow({'user' : 'admin', 'pwd' : '123'})});
assert(err1.toString().indexOf('Error: 18') > -1, "Expected to fail with bad pwd");

var err2 = assert.throws(function(){adminDb._authOrThrow({'user' : 'not admin', 'pwd' : 'abc'})});
assert(err2.toString().indexOf('Error: 18') > -1, "Expected to fail with bad user");

//Bad protocol, nonce not called prior to authenticate
authres3 = adminDb.runCommand( { 'authenticate' : 1, 'user' : 'admin', 'key' : 'b' } );
assert.eq(17, authres3.code, "Expected bad command error code");

//SASL PLAIN
assert(adminDb.auth({'mechanism' : 'PLAIN', 'user' : 'admin', 'pwd' : 'password'}));
err4 = assert.throws(function(){adminDb._authOrThrow({'mechanism' : 'PLAIN', 'user' : 'admin',
						 'pwd' : 'bad password'})});
assert(err4.toString().indexOf('Error: 18') > -1, "Expected to fail with bad pwd");

//SASL CRAM-MD5
assert(adminDb.auth({'mechanism' : 'CRAM-MD5', 'user' : 'admin', 'pwd' : 'password'}));
err5 = assert.throws(function(){adminDb._authOrThrow({'mechanism' : 'CRAM-MD5', 
						      'user' : 'BADadmin',
						      'pwd' : 'password'})});
assert(err5.toString().indexOf('Error: 18') > -1, "Expected to fail with bad pwd");
