const lodash = require("lodash");
const displayName = lodash.get({ user: { name: "PathGuard demo" } }, "user.name");
const renderGreeting = lodash.template("Hello <%= user %>!");
console.log(displayName, renderGreeting({ user: "demo" }));
