Node.js Auth API
 Node.js Auth & Role-Based Access System
A production-ready Node.js authentication backend with:

Email OTP verification

Login/Signup with JWT tokens

Refresh/Logout routes

Forgot & reset password flow

Role-based access (admin/user)

Protected route middleware

Secure rate limiting

Nodemailer integration

MongoDB + Mongoose

📂 Folder Structure

/project-root
│
├── controllers/
│   └── authController.js
│   └── adminController.js
│
├── middleware/
│   └── authMiddleware.js
│   └── roleMiddleware.js
│   └── rateLimiter.js
│
├── models/
│   └── User.js
│
├── routes/
│   └── authRoutes.js
│   └── adminRoutes.js
│   └── userRoutes.js
│
├── utils/
│   └── sendEmail.js
│
├── .env
├── server.js
├── package.json
🚀 Features
Feature	Description
🔐 Signup/Login	Email, password (JWT)
✅ OTP Verification	Email-based verification before login
🔁 Token Refresh	Refresh token endpoint for access token renewal
🔓 Logout	Invalidate session (DB or cookie-based)
🛠️ Role-Based Access	Admin/User routes via middleware
📩 Forgot/Reset Password	Email reset link with secure token
🚧 Protected Routes	Auth middleware and role checks
✉️ Nodemailer Integration	Email for OTP & password reset
📊 Rate Limiting	Brute-force protection using express-rate-limit

🔐 API Routes
Auth Routes
Route	Method	Access	Description
/signup	POST	Public	Register user
/verify-otp	POST	Public	Verify email OTP
/login	POST	Public	Login, returns tokens
/refresh-token	POST	Public	Get new access token
/logout	POST	Private	Logout and invalidate
/forgot-password	POST	Public	Request password reset
/reset-password	POST	Public	Reset password

Admin Routes
Route	Method	Role	Description
/admin/dashboard	GET	Admin	Admin-only dashboard
/admin/make-admin	POST	Admin	Promote user to admin

User Routes
Route	Method	Access	Description
/user/me	GET	Private	Authenticated user route

🛠️ Technologies Used
Node.js + Express

MongoDB + Mongoose

JWT (jsonwebtoken)

Nodemailer

Bcrypt (password hashing)

Express-rate-limit

