const User = require("../models/User");

const promoteToAdmin = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOneAndUpdate(
      { email },
      { role: "admin" },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ message: `${user.email} is now an admin` });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};
module.exports = {
  promoteToAdmin,
};
