// dumprestore5.js

t = new ToolTest( "dumprestore5" );

t.startDB( "foo" );

db = t.db.getSiblingDB("admin")

db.addUser({user: 'user',pwd: 'password', roles: jsTest.basicUserRoles});

assert.eq(1, db.system.users.count(), "setup")
assert.eq(2, db.system.indexes.count(), "setup2")

t.runTool( "dump" , "--out" , t.ext );

db.dropDatabase()

assert.eq(0, db.system.users.count(), "didn't drop users")
assert.eq(0, db.system.indexes.count(), "didn't drop indexes")

t.runTool("restore", "--dir", t.ext)

assert.soon("db.system.users.findOne()", "no data after restore");
assert.eq(1, db.system.users.find({user:'user'}).count(), "didn't restore users")
assert.eq(2, db.system.indexes.count(), "didn't restore indexes")

db.dropUser('user')
db.addUser({user: 'user2', pwd: 'password2', roles: jsTest.basicUserRoles});

t.runTool("restore", "--dir", t.ext, "--drop")

assert.soon("1 == db.system.users.find({user:'user'}).count()", "didn't restore users 2")
assert.eq(0, db.system.users.find({user:'user2'}).count(), "didn't drop users")
assert.eq(2, db.system.indexes.count(), "didn't maintain indexes")

t.stop();

