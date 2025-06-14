const express = require("express");
const router = express.Router();
const authenticate = require("../middleware/authMiddleware");
const checkRole = require("../middleware/roleMiddleware");
const { promoteToAdmin } = require("../controllers/adminController");




// Example: only admin can access this
router.get("/dashboard", authenticate, checkRole("admin"), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.userId}` });
});

router.post("/make-admin", authenticate, checkRole("admin"), promoteToAdmin);


module.exports = router;
