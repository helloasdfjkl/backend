let userFollowing = {
  Mack: ["Jack", "Zack"],
};

// Get the list of users that the specified user is following
function getFollowing(req, res) {
  const username = req.username;
  const following = userFollowing[username] || [];
  res.send({ username: username, following: following });
}

// Add a new user to the following list
function addFollowing(req, res) {
  const username = req.username;
  const userToFollow = req.body.username; // Username of the user to follow

  if (!userFollowing[username]) {
    userFollowing[username] = [];
  }

  if (userFollowing[username].includes(userToFollow)) {
    return res.status(400).send({ error: "Already following this user" });
  }

  userFollowing[username].push(userToFollow);
  res.send({ username: username, following: userFollowing[username] });
}

// Remove a user from the following list
function removeFollowing(req, res) {
  const username = req.username;
  const userToUnfollow = req.body.username; // Username of the user to unfollow

  if (
    !userFollowing[username] ||
    !userFollowing[username].includes(userToUnfollow)
  ) {
    return res.status(404).send({ error: "User not followed" });
  }

  userFollowing[username] = userFollowing[username].filter(
    (user) => user !== userToUnfollow
  );
  res.send({ username: username, following: userFollowing[username] });
}

module.exports = (app) => {
  app.get("/following", getFollowing);
  app.put("/following", addFollowing);
  app.delete("/following", removeFollowing);
};
