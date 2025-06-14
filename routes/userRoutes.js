const express = require("express");
const router = express.Router();
const authenticate = require("../middleware/authMiddleware");

router.get("/me", authenticate, (req, res) => {
  res.json({ message: "You are authenticated", user: req.user });
});

module.exports = router;
