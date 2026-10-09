const lodash = require("lodash");
const displayName = lodash.get({ user: { name: "PathGuard demo" } }, "user.name");
console.log(displayName);
