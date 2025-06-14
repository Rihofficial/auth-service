const express = require("express");
const router = express.Router();
const authenticate = require("../middleware/authMiddleware");

router.get("/dashboard", authenticate, (req, res) => {
  res.json({ message: `Welcome user ${req.user.userId}` });
});

module.exports = router;
