const express = require("express");
const router = express.Router();
const {
  signup,
  verifyOtp,
  login,
  logout,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");
const { refreshToken } = require("../controllers/authController");
const authenticate = require("../middleware/authMiddleware");


router.post("/refresh-token", refreshToken);
router.post("/signup", signup);
router.post("/verify-otp", verifyOtp);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

// protect logout route
router.post("/logout", authenticate, logout);



module.exports = router;
