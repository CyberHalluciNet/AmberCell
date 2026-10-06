db = db.getSiblingDB('corp_app');
db.users.insertMany([
  { username: 'admin', role: 'administrator' },
  { username: 'finance', role: 'finance' },
]);
db.transactions.insertOne({ amount: 500, memo: 'seed' });
