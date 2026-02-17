require('dotenv').config();

console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
console.log(
  'GOOGLE_CLIENT_SECRET:',
  process.env.GOOGLE_CLIENT_SECRET ? 'LOADED' : 'MISSING'
);
console.log('EMAIL_USER:', process.env.EMAIL_USER);
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? 'LOADED' : 'MISSING');

const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const path = require('path');
const multer = require('multer'); 

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

const axios = require("axios");
const moment = require("moment");
const PORT = process.env.PORT || 3000;

// Multer storage configuration

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, path.join(__dirname, 'public/pdf'));
    } else {
      cb(null, path.join(__dirname, 'public/images'));
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueName + ext);
  }
});

// File filter (only images + PDFs allowed)

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/jpg',
    'image/webp',
    'application/pdf'
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only images and PDF files are allowed'), false);
  }
};

// UPLOAD MILDWARE
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB max
});


// MPESA ACCESS ROUTE


// --- M-PESA ACCESS TOKEN HELPER ---

async function getMpesaAccessToken() {
  const auth = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const url =
    process.env.MPESA_ENV === "live"
      ? "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
      : "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";

  const response = await axios.get(url, {
    headers: {
      Authorization: `Basic ${auth}`,
    },
  });

  return response.data.access_token;
}

// --- TEST ROUTE FOR ACCESS TOKEN ---

app.get("/api/mpesa/token", async (req, res) => {
  try {
    const token = await getMpesaAccessToken();
    res.json({ access_token: token });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json(error.response?.data || error.message);
  }
});


/* 🔹 PostgreSQL connection */


const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // used in production
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,

  // fallback for local development
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});


/* =====================================================
   🔹 STRIPE WEBHOOK (MUST COME BEFORE BODY PARSERS)
   ===================================================== */
app.post(
  '/stripe/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('❌ Webhook signature error:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      console.log('✅ Payment confirmed:', session.id);

      const userId = session.metadata.user_id;
      const courseId = session.metadata.course_id;

      await pool.query(
        `INSERT INTO payments
         (user_id, course_id, stripe_session_id, amount, currency, status)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [
          userId,
          courseId,
          session.id,
          session.amount_total,
          session.currency,
          'paid'
        ]
      );
      await pool.query(
  `INSERT INTO enrollments (user_id, course_id)
   VALUES ($1, $2)
   ON CONFLICT DO NOTHING`,
  [userId, courseId]
  
);
 console.log('✅ Enrollment inserted via webhook:', userId, courseId);
    }

    res.json({ received: true });
  }
);

app.use(express.static(path.join(__dirname, 'public')));


/* 🔹 Passport setup */
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, result.rows[0]);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const username = profile.displayName;

        const existingUser = await pool.query(
          'SELECT * FROM users WHERE email = $1',
          [email]
        );

        if (existingUser.rows.length > 0) {
          return done(null, existingUser.rows[0]);
        }

        const newUser = await pool.query(
          `INSERT INTO users (username, email)
           VALUES ($1, $2)
           RETURNING *`,
          [username, email]
        );

        done(null, newUser.rows[0]);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

/* 🔹 Body parsers (AFTER webhook) */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


/* 🔹 Session middleware (REQUIRED for Passport) */
app.use(
  session({
    name: 'mywebsite-session',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false // true only when using HTTPS
    }
  })
);

/* 🔹 Passport middleware (AFTER session) */
app.use(passport.initialize());
app.use(passport.session());


/* 🔹 Auth middleware */
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ADMIN MIDDLEWARE
function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.status(403).send('Access denied');
}
// ADMIN DASHBOARD
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const usersCount = await pool.query('SELECT COUNT(*) FROM users');
    const coursesCount = await pool.query('SELECT COUNT(*) FROM courses');
    const enrollmentsCount = await pool.query('SELECT COUNT(*) FROM enrollments');
    const paymentsCount = await pool.query('SELECT COUNT(*) FROM payments');

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Admin Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
        >
      </head>
      <body class="bg-light">

        <div class="container mt-5">
          <h2 class="mb-4 text-center">🛠 Admin Dashboard</h2>

          <div class="row text-center">

            <div class="col-md-3 mb-3">
              <div class="card shadow">
                <div class="card-body">
                  <h5>Total Users</h5>
                  <h3>${usersCount.rows[0].count}</h3>
                </div>
              </div>
            </div>

            <div class="col-md-3 mb-3">
              <div class="card shadow">
                <div class="card-body">
                  <h5>Total Courses</h5>
                  <h3>${coursesCount.rows[0].count}</h3>
                </div>
              </div>
            </div>

            <div class="col-md-3 mb-3">
              <div class="card shadow">
                <div class="card-body">
                  <h5>Enrollments</h5>
                  <h3>${enrollmentsCount.rows[0].count}</h3>
                </div>
              </div>
            </div>

            <div class="col-md-3 mb-3">
              <div class="card shadow">
                <div class="card-body">
                  <h5>Payments</h5>
                  <h3>${paymentsCount.rows[0].count}</h3>
                </div>
              </div>
            </div>

          </div>

          <hr class="my-4">

          <div class="d-flex flex-wrap justify-content-center gap-3">

            <a href="/admin/courses/new" class="btn btn-success w-100 w-md-auto">

              ➕ Upload Course
            </a>
            <a href="/admin/courses" class="btn btn-primary  w-100 w-md-auto">
              📚 Manage Courses
            </a>
            <a href="/admin/enrollments" class="btn btn-warning  w-100 w-md-auto">
              👥 View Enrollments
            </a>

             <a href="/admin/sales" class="btn btn-primary  w-100 w-md-auto">
              📊 View Sales
            </a>

            <a href="/admin/profile-items" class="btn btn-info  w-100 w-md-auto">
  🧩 Manage Profile Content
</a>

  <a href="/admin/expenses" class="btn btn-success  w-100 w-md-auto" >Expenditure Tracker</a>


          </div>

          <div class="text-center mt-4">
            <a href="/home">← Back to site</a>
          </div>

        </div>

      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Admin dashboard error');
  }
});

// MANAGE COURSES PAGE

app.get('/admin/courses', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, price FROM courses ORDER BY id'
    );

    const rows = result.rows.map(course => `
      <tr>
        <td>${course.id}</td>
        <td>${course.name}</td>
        <td>$${course.price}</td>
        <td>

        <a href="/admin/courses/edit/${course.id}"
     class="btn btn-sm btn-primary">
    Edit
  </a>
       <form
  action="/admin/courses/delete/${course.id}"
  method="POST"
  onsubmit="return confirm('Delete this course?')"
  style="display:inline;"
>
  <button class="btn btn-sm btn-danger">
    Delete
  </button>
</form>

        </td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Manage Courses</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">
      </head>
      <body class="container mt-4">
        <h2>📚 Manage Courses</h2>
        <a href="/admin" class="btn btn-secondary mb-3">← Back</a>

        <table class="table table-bordered">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Price</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to load courses');
  }
});

// DELETE ROUTE
app.post(
  '/admin/courses/delete/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const courseId = req.params.id;

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      
      // DELETE LESSON
app.post(
  '/admin/lessons/delete/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const lessonId = req.params.id;

    try {
      // Get course_id before deleting (for redirect)
      const result = await pool.query(
        'SELECT course_id FROM lessons WHERE id = $1',
        [lessonId]
      );

      if (result.rows.length === 0) {
        return res.status(404).send('Lesson not found');
      }

      const courseId = result.rows[0].course_id;

      await pool.query(
        'DELETE FROM lessons WHERE id = $1',
        [lessonId]
      );

      console.log(`✅ Lesson ${lessonId} deleted`);

      res.redirect(`/admin/courses/edit/${courseId}`);

    } catch (err) {
      console.error('❌ Failed to delete lesson:', err);
      res.status(500).send('Failed to delete lesson');
    }
  }
);


      // 1️⃣ Remove enrollments first (FK safe)
      await client.query(
        'DELETE FROM enrollments WHERE course_id = $1',
        [courseId]
      );

      // 2️⃣ Remove payments related to course
      await client.query(
        'DELETE FROM payments WHERE course_id = $1',
        [courseId]
      );

      // 3️⃣ Delete course itself
      const result = await client.query(
        'DELETE FROM courses WHERE id = $1 RETURNING id',
        [courseId]
      );

      if (result.rowCount === 0) {
        await client.query('ROLLBACK');
        return res.status(404).send('Course not found');
      }

      await client.query('COMMIT');

      console.log(`✅ Course ${courseId} deleted by admin`);

      res.redirect('/admin/courses');

    } catch (err) {
      await client.query('ROLLBACK');
      console.error('❌ Delete course failed:', err);
      res.status(500).send('Failed to delete course');
    } finally {
      client.release();
    }
  }
);

// EDIT COURSE



// SAVING EDIT CHANGES

app.post(
  '/admin/courses/edit/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const courseId = req.params.id;
    const { name, description, price, image_url } = req.body;

    try {
      await pool.query(
        `UPDATE courses
         SET name=$1, description=$2, price=$3, image_url=$4
         WHERE id=$5`,
        [name, description, price, image_url, courseId]
      );

      res.redirect('/admin/courses');

    } catch (err) {
      console.error(err);
      res.status(500).send('Failed to update course');
    }
  }
);


// VIEW ENROLLMENTS

app.get('/admin/enrollments', isAuthenticated, isAdmin, async (req, res) => {
  try {
   const result = await pool.query(`
  SELECT
    u.id AS user_id,
    c.id AS course_id,
    u.username,
    u.email,
    c.name AS course_name,
    e.enrolled_at
  FROM enrollments e
  JOIN users u ON u.id = e.user_id
  JOIN courses c ON c.id = e.course_id
  ORDER BY e.enrolled_at DESC
`);


  const rows = result.rows.map(row => `
  <tr>
    <td>${row.username}</td>
    <td>${row.email}</td>
    <td>${row.course_name}</td>
    <td>${new Date(row.enrolled_at).toLocaleString()}</td>
    <td>
      <form
        method="POST"
        action="/admin/enrollments/delete"
        onsubmit="return confirm('Unenroll this user from the course?')"
        style="display:inline"
      >
        <input type="hidden" name="user_id" value="${row.user_id}">
        <input type="hidden" name="course_id" value="${row.course_id}">
        <button class="btn btn-sm btn-danger">
          ❌ Unenroll
        </button>
      </form>
    </td>
  </tr>
`).join('');


    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Enrollments</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">
      </head>
      <body class="container mt-4">
        <h2>👥 Enrollments</h2>
        <a href="/admin" class="btn btn-secondary mb-3">← Back</a>

        <table class="table table-striped">
       <thead>
  <tr>
    <th>User</th>
    <th>Email</th>
    <th>Course</th>
    <th>Date</th>
    <th>Action</th>
  </tr>
</thead>

          <tbody>
            ${rows || '<tr><td colspan="4">No enrollments</td></tr>'}
          </tbody>
        </table>
      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to load enrollments');
  }
});

// ADMIN UNENROLL USER FROM COURSE
app.post(
  '/admin/enrollments/delete',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const { user_id, course_id } = req.body;

    try {
      await pool.query(
        `DELETE FROM enrollments
         WHERE user_id = $1 AND course_id = $2`,
        [user_id, course_id]
      );

      console.log(`✅ Admin unenrolled user ${user_id} from course ${course_id}`);
      res.redirect('/admin/enrollments');
    } catch (err) {
      console.error('❌ Failed to unenroll:', err);
      res.status(500).send('Failed to unenroll user');
    }
  }
);



// ADMIN UPLOAD PAGE
app.get('/admin/courses/new', isAuthenticated, isAdmin, async (req, res) => {
  const categories = await pool.query('SELECT * FROM categories');

  const options = categories.rows
    .map(c => `<option value="${c.id}">${c.name}</option>`)
    .join('');

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Create Course</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Bootstrap -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

  <style>
    body {
      background: #f5f7fa;
    }
    .card {
      border-radius: 14px;
    }
  </style>
</head>

<body class="container py-5">

  <!-- HEADER -->
  <div class="position-relative text-center mb-4">
  <h2 class="fw-semibold">📘 Create New Course</h2>

   <a href="/admin" class="btn btn-outline-secondary btn-sm">← Admin</a>
  </div>
</div>

  <!-- FORM CARD -->
  <div class="row justify-content-center">
    <div class="col-lg-8 col-md-10">
      <div class="card shadow-sm">
        <div class="card-body p-4">

          <form method="POST" action="/admin/courses" class="row g-3">

            <div class="col-12">
              <label class="form-label">Course Name</label>
              <input name="name" class="form-control" placeholder="e.g. Full Stack Web Development" required>
            </div>

            <div class="col-12">
              <label class="form-label">Description</label>
              <textarea name="description" rows="4" class="form-control" placeholder="Course description..." required></textarea>
            </div>

            <div class="col-md-6">
              <label class="form-label">Price (KES)</label>
              <input name="price" type="number" class="form-control" placeholder="e.g. 5000" required>
            </div>

            <div class="col-md-6">
              <label class="form-label">Image URL</label>
              <input name="image_url" class="form-control" placeholder="https://..." required>
            </div>

            <div class="col-12">
              <label class="form-label">Category</label>
              <select name="category_id" class="form-select" required>
                <option value="">-- Select Category --</option>
                ${options}
              </select>
            </div>

            <div class="col-12 d-grid mt-3">
              <button class="btn btn-primary btn-lg">
                Create Course
              </button>
            </div>

          </form>

        </div>
      </div>
    </div>
  </div>

</body>
</html>
  `);
});
// LESSONS UPLOAD

app.post(
  '/admin/lessons',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const { course_id, title, video_id, lesson_order } = req.body;

    await pool.query(
      `INSERT INTO lessons
       (course_id, title, video_provider, video_id, lesson_order)
       VALUES ($1, $2, 'youtube', $3, $4)`,
      [course_id, title, video_id, lesson_order]
    );

    res.redirect(`/admin/courses/edit/${course_id}`);
  }
);

app.get(
  '/admin/courses/edit/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const courseId = req.params.id;

    try {
      const courseResult = await pool.query(
        'SELECT * FROM courses WHERE id = $1',
        [courseId]
      );

      if (courseResult.rows.length === 0) {
        return res.status(404).send('Course not found');
      }

      const course = courseResult.rows[0];

      // 🔹 Fetch lessons
     const lessonsResult = await pool.query(
  `SELECT id, title, lesson_order, video_id
   FROM lessons
   WHERE course_id = $1
   ORDER BY lesson_order`,
  [courseId]
);


      const lessonsHtml = lessonsResult.rows.length
  ? lessonsResult.rows.map(l => `
      <li class="mb-2">
        <strong>Lesson ${l.lesson_order}:</strong> ${l.title}
        <br>
        <small>YouTube ID: ${l.video_id}</small>

        <form
          action="/admin/lessons/delete/${l.id}"
          method="POST"
          style="display:inline"
          onsubmit="return confirm('Delete this lesson?')"
        >
          <button class="btn btn-sm btn-danger ms-2">
            🗑 Delete
          </button>
        </form>
      </li>
    `).join('')
  : '<p>No lessons uploaded yet.</p>';

      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Edit Course</title>
          <link
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
            rel="stylesheet">
        </head>
        <body class="container mt-4">

          <h2>✏️ Edit Course: ${course.name}</h2>

          <form method="POST" action="/admin/courses/edit/${course.id}">
            <div class="mb-3">
              <label>Name</label>
              <input class="form-control" name="name" value="${course.name}" required>
            </div>

            <div class="mb-3">
              <label>Description</label>
              <textarea class="form-control" name="description" required>${course.description}</textarea>
            </div>

            <div class="mb-3">
              <label>Price</label>
              <input type="number" class="form-control" name="price" value="${course.price}" required>
            </div>

            <div class="mb-3">
              <label>Image URL</label>
              <input class="form-control" name="image_url" value="${course.image_url}">
            </div>

            <button class="btn btn-success">Save Changes</button>
            <a href="/admin/courses" class="btn btn-secondary">Back</a>
          </form>

          <hr class="my-4">

          <h4>📹 Uploaded Lessons</h4>
          <ul>${lessonsHtml}</ul>

          <hr>

          <h4>➕ Upload New Lesson</h4>

          <form method="POST" action="/admin/lessons">
            <input type="hidden" name="course_id" value="${course.id}">

            <div class="mb-2">
              <label>Lesson Title</label>
              <input class="form-control" name="title" required>
            </div>

            <div class="mb-2">
              <label>YouTube Video ID</label>
              <input
                class="form-control"
                name="video_id"
                placeholder="e.g. dQw4w9WgXcQ"
                required>
            </div>

            <div class="mb-3">
              <label>Lesson Order</label>
              <input type="number" class="form-control" name="lesson_order" required>
            </div>

            <button class="btn btn-primary">Upload Lesson</button>
          </form>

        </body>
        </html>
      `);

    } catch (err) {
      console.error(err);
      res.status(500).send('Failed to load course');
    }
  }
);

// DELETE LESSON
app.post(
  '/admin/lessons/delete/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const lessonId = req.params.id;

    try {
      const result = await pool.query(
        'SELECT course_id FROM lessons WHERE id = $1',
        [lessonId]
      );

      if (result.rows.length === 0) {
        return res.status(404).send('Lesson not found');
      }

      const courseId = result.rows[0].course_id;

      await pool.query(
        'DELETE FROM lessons WHERE id = $1',
        [lessonId]
      );

      res.redirect(`/admin/courses/edit/${courseId}`);
    } catch (err) {
      console.error(err);
      res.status(500).send('Failed to delete lesson');
    }
  }
);


// SAVE COURSE TO DB
app.post('/admin/courses', isAuthenticated, isAdmin, async (req, res) => {
  const { name, description, price, image_url, category_id } = req.body;

  try {
    await pool.query(
      `INSERT INTO courses (name, description, price, image_url, category_id)
       VALUES ($1,$2,$3,$4,$5)`,
      [name, description, price, image_url,category_id]
    );

    res.redirect('/courses');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to create course');
  }
});

/* 🔹 Step 2: Payment Page (Fetch course from DB dynamically) */
/* 🔹 Dynamic Payment Page with Course Image */
/* 🔹 Payment Page (Dynamic Course with Image) */
app.get('/payment', isAuthenticated, async (req, res) => {
  const { course_id } = req.query;

  try {
    // Fetch the course from the database
    const result = await pool.query(
      'SELECT id, name, description, price, image_url FROM courses WHERE id = $1',
      [course_id]
    );

    if (result.rows.length === 0) return res.send('Course not found');

    const course = result.rows[0];

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Enroll - ${course.name}</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
        >
        <link rel="stylesheet" href="/css/styles.css">
      </head>
      <body class="container mt-5">
        <div class="card mx-auto" style="max-width: 600px;">
          <img src="${course.image_url}" class="card-img-top img-fluid" alt="${course.name}">
          <div class="card-body">
            <h3 class="card-title">${course.name}</h3>
            <p class="card-text">${course.description}</p>
            <p><strong>Price:</strong> $${course.price}</p>

            <form action="/pay/card" method="POST">
              <input type="hidden" name="course_id" value="${course.id}">
              <input type="hidden" name="course_name" value="${course.name}">
              <input type="hidden" name="amount" value="${course.price}">
              <button class="btn btn-primary btn-lg w-100">
                💳 Pay with Card
              </button>
            </form>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// ENROLMENT MILDWARE
function isEnrolled() {
  return async (req, res, next) => {
    try {
      const userId = req.user.id;
      const courseId = req.params.courseId; // or req.params.id

      const result = await pool.query(
        'SELECT 1 FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [userId, courseId]
      );

      if (result.rows.length === 0) {
        return res.redirect('/courses');
      }

      next();
    } catch (err) {
      console.error('Enrollment check failed:', err);
      res.status(500).send('Server error');
    }
  };
}
 


// ACCESS COURSE ROUTE
app.get(
  '/course/:courseId',
  isAuthenticated,
  isEnrolled(),
  async (req, res) => {
    const { courseId } = req.params;

    try {
      // 🔹 Get course details (INCLUDING image)
      const courseResult = await pool.query(
        `SELECT id, name, description, image_url
         FROM courses
         WHERE id = $1`,
        [courseId]
      );

      if (courseResult.rows.length === 0) {
        return res.send('Course not found');
      }

      const course = courseResult.rows[0];

      // 🔹 Get lessons
      const lessonsResult = await pool.query(
        `SELECT id, title, lesson_order
         FROM lessons
         WHERE course_id = $1
         ORDER BY lesson_order`,
        [courseId]
      );

      // 🔹 Build lessons list
      const lessonsHtml = lessonsResult.rows.length
        ? lessonsResult.rows
            .map(
              (lesson) => `
                <li class="list-group-item">
                  <a
                    href="/course/${courseId}/lesson/${lesson.id}"
                    class="text-decoration-none"
                  >
                    ▶ Lesson ${lesson.lesson_order}: ${lesson.title}
                  </a>
                </li>
              `
            )
            .join('')
        : `<li class="list-group-item text-muted">No lessons yet</li>`;

      // 🔹 Render responsive page
      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <title>${course.name}</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">

          <link
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
            rel="stylesheet"
          >
        </head>

        <body class="bg-light">

          <div class="container py-4">

            <div class="row g-4">

              <!-- 📘 Course Info -->
              <div class="col-12 col-lg-8">
                <div class="card shadow-sm h-100">
                  <img
                    src="${course.image_url?.trim() || '/images/default-course.jpg'}"
                    class="card-img-top img-fluid"
                    alt="${course.name}"
                  >

                  <div class="card-body">
                    <h2 class="card-title">${course.name}</h2>
                    <p class="card-text">${course.description}</p>
                  </div>
                </div>
              </div>

              <!-- 📚 Lessons Sidebar -->
              <div class="col-12 col-lg-4">
                <div class="card shadow-sm">
                  <div class="card-header bg-primary text-white">
                    Lessons
                  </div>

                  <ul class="list-group list-group-flush">
                    ${lessonsHtml}
                  </ul>
                </div>
              </div>

            </div>

            <!-- 🔙 Back button -->
            <div class="mt-4 text-center">
              <a href="/my-courses" class="btn btn-outline-secondary">
                ← Back to My Courses
              </a>
            </div>

          </div>

        </body>
        </html>
      `);
    } catch (err) {
      console.error(err);
      res.send('Error loading course');
    }
  }
);

//VIDEO LESSON PAGAE

app.get(
  '/course/:courseId/lesson/:lessonId',
  isAuthenticated,
  isEnrolled(),
  async (req, res) => {
    const { courseId, lessonId } = req.params;

    const lessonResult = await pool.query(
      `SELECT title, video_id
       FROM lessons
       WHERE id = $1 AND course_id = $2`,
      [lessonId, courseId]
    );

    if (lessonResult.rows.length === 0) {
      return res.send('Lesson not found');
    }

    const lesson = lessonResult.rows[0];

    res.send(`
      <h2>${lesson.title}</h2>

      <iframe
        width="100%"
        height="450"
        src="https://www.youtube.com/embed/${lesson.video_id}"
        frameborder="0"
        allowfullscreen>
      </iframe>

      <br><br>
      <a href="/course/${courseId}">← Back to Lessons</a>
    `);
  }
);


// ==================== GET /admin/profile-items ====================
app.get('/admin/profile-items', isAuthenticated, isAdmin, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM profile_items ORDER BY type, created_at DESC'
  );

  const rows = result.rows.map(item => `
    <tr>
      <td><span class="badge bg-secondary text-capitalize">${item.type}</span></td>
      <td>${item.title}</td>
      <td>
        ${
          item.file_path
            ? item.file_path.endsWith('.pdf')
              ? `<a href="${item.file_path}" target="_blank" class="btn btn-sm btn-outline-primary">View PDF</a>`
              : `<img src="${item.file_path}" class="img-thumbnail" style="max-width:60px;">`
            : '<span class="text-muted">—</span>'
        }
      </td>
      <td>
        <form
          method="POST"
          action="/admin/profile-items/delete/${item.id}"
          onsubmit="return confirm('Delete item?')"
        >
          <button class="btn btn-sm btn-outline-danger">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Manage Profile Content</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

  <style>
    body { background:#f5f7fa; }
    .card { border-radius:14px; }
  </style>
</head>

<body class="container py-5">

  <!-- HEADER -->
  <div class="position-relative text-center mb-4">
    <h2 class="fw-semibold">👤 Manage Profile Content</h2>
 <a href="/admin" class="btn btn-outline-secondary btn-sm">← Admin</a>
  </div>
  </div>

  <!-- ADD ITEM -->
  <div class="card shadow-sm mb-4">
    <div class="card-body p-4">
      <h5 class="mb-3">Add Profile Item</h5>

      <form method="POST" action="/admin/profile-items" enctype="multipart/form-data" class="row g-3">

        <div class="col-md-4">
          <label class="form-label">Type</label>
          <select name="type" id="type-select" class="form-select" required>
            <option value="hobby">Hobbies</option>
            <option value="book">Books</option>
            <option value="work">Work</option>
            <option value="skill">Skills</option>
            <option value="certification">Certification</option>
          </select>
        </div>

        <div class="col-md-8">
          <label class="form-label">Title</label>
          <input name="title" class="form-control" placeholder="Title" required>
        </div>

        <div class="col-12">
          <label class="form-label">Description</label>
          <textarea name="description" class="form-control" rows="3" placeholder="Optional description"></textarea>
        </div>

        <div class="col-md-6">
          <label class="form-label">File (Image or PDF)</label>
          <input type="file" name="file" class="form-control" accept="image/*,.pdf">
        </div>

        <!-- Skill Rating -->
        <div class="col-md-6" id="rating-container" style="display:none;">
          <label class="form-label">Skill Rating</label>
          <select name="rating" class="form-select">
            <option value="5">5 - Expert</option>
            <option value="4">4 - Advanced</option>
            <option value="3">3 - Intermediate</option>
            <option value="2">2 - Beginner</option>
            <option value="1">1 - Novice</option>
          </select>
        </div>

        <div class="col-12 d-grid mt-3">
          <button class="btn btn-primary btn-lg">Add Item</button>
        </div>

      </form>
    </div>
  </div>

  <!-- TABLE -->
  <div class="card shadow-sm">
    <div class="card-body">
      <h5 class="mb-3">Existing Items</h5>

      <div class="table-responsive">
        <table class="table table-hover align-middle">
          <thead class="table-light">
            <tr>
              <th>Type</th>
              <th>Title</th>
              <th>File</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="4" class="text-center">No items yet</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const typeSelect = document.getElementById('type-select');
    const ratingContainer = document.getElementById('rating-container');

    function toggleRating() {
      ratingContainer.style.display = typeSelect.value === 'skill' ? 'block' : 'none';
    }

    typeSelect.addEventListener('change', toggleRating);
    toggleRating();
  </script>
   
</body>

</html>
  `);
});

// ==================== POST /admin/profile-items ====================
app.post(
  '/admin/profile-items',
  isAuthenticated,
  isAdmin,
  upload.single('file'), // Multer handles file upload
  async (req, res) => {
    const { type, title, description, rating } = req.body;

    let filePath = null;
    if (req.file) {
      if (req.file.mimetype === 'application/pdf') {
        filePath = `/pdf/${req.file.filename}`;
      } else {
        filePath = `/images/${req.file.filename}`;
      }
    }

    const ratingValue = type === 'skill' ? rating : null;

    await pool.query(
      `INSERT INTO profile_items (type, title, description, file_path, rating)
       VALUES ($1, $2, $3, $4, $5)`,
      [type, title, description, filePath, ratingValue]
    );

    res.redirect('/admin/profile-items');
  }
);

// ==================== DELETE /admin/profile-items/:id ====================
app.post(
  '/admin/profile-items/delete/:id',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    await pool.query(
      'DELETE FROM profile_items WHERE id = $1',
      [req.params.id]
    );

    res.redirect('/admin/profile-items');
  }
);


// ==================== GET /admin/expenses ====================
app.get('/admin/expenses', isAuthenticated, isAdmin, async (req, res) => {
  // ================== MAIN DATA ==================
  const expensesResult = await pool.query(`
    SELECT * FROM expenses
    ORDER BY expense_date DESC
  `);

  const totalResult = await pool.query(`
    SELECT COALESCE(SUM(amount), 0) AS total FROM expenses
  `);

  // ================== MONTHLY SUMMARY ==================
  const monthlyResult = await pool.query(`
    SELECT
      TO_CHAR(expense_date, 'YYYY-MM') AS month,
      SUM(amount) AS total
    FROM expenses
    GROUP BY month
    ORDER BY month DESC
    LIMIT 6
  `);

  // ================== CATEGORY TOTALS ==================
  const categoryResult = await pool.query(`
    SELECT category, SUM(amount) AS total
    FROM expenses
    GROUP BY category
    ORDER BY total DESC
  `);

  const total = totalResult.rows[0].total;

  // ================== TABLE ROWS ==================
  const rows = expensesResult.rows.map(exp => `
    <tr>
      <td>${exp.title}</td>
      <td><span class="badge bg-secondary">${exp.category}</span></td>
      <td>KES ${Number(exp.amount).toLocaleString()}</td>
      <td>${exp.expense_date.toLocaleDateString('en-CA')}</td>
      <td>
        <form method="POST" action="/admin/expenses/delete/${exp.id}">
          <button class="btn btn-sm btn-outline-danger">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');

  // ================== MONTHLY CARDS ==================
  const monthlyCards = monthlyResult.rows.map(m => `
    <div class="col-md-4 mb-3">
      <div class="card shadow-sm h-100">
        <div class="card-body text-center">
          <small class="text-muted">${m.month}</small>
          <h5 class="mt-2">KES ${Number(m.total).toLocaleString()}</h5>
        </div>
      </div>
    </div>
  `).join('');

  // ================== CATEGORY LIST ==================
  const categoryList = categoryResult.rows.map(c => `
    <li class="list-group-item d-flex justify-content-between align-items-center">
      ${c.category}
      <span class="fw-bold">KES ${Number(c.total).toLocaleString()}</span>
    </li>
  `).join('');

  // ================== PAGE ==================
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Expenses</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Bootstrap -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

  <style>
    body {
      background: #f5f7fa;
    }
    .card {
      border-radius: 14px;
    }
    .badge {
      font-size: 0.85rem;
    }
  </style>
</head>

<body class="container py-4">

  <!-- HEADER -->
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>💸 Expense Tracker</h2>
    <a href="/admin" class="btn btn-outline-secondary btn-sm">← Admin</a>
  </div>

  <!-- TOTAL -->
  <div class="alert alert-primary text-center fs-5">
    Total Spent: <strong>KES ${Number(total).toLocaleString()}</strong>
  </div>

  <!-- ADD EXPENSE -->
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <h5 class="mb-3">Add Expense</h5>

      <form method="POST" action="/admin/expenses" class="row g-3">
        <div class="col-md-3">
          <input name="title" class="form-control" placeholder="Title" required>
        </div>

        <div class="col-md-2">
          <select name="category" class="form-select" required>
            <option>Food</option>
            <option>Transport</option>
            <option>Bills</option>
            <option>Hosting</option>
            <option>Education</option>
            <option>Misc</option>
          </select>
        </div>

        <div class="col-md-2">
          <input type="number" name="amount" step="0.01" class="form-control" placeholder="KES" required>
        </div>

        <div class="col-md-3">
          <input type="date" name="expense_date" class="form-control">
        </div>

        <div class="col-md-2 d-grid">
          <button class="btn btn-primary">Add Expense</button>
        </div>
      </form>
    </div>
  </div>

  <!-- SUMMARY -->
  <div class="row mb-4">
    <div class="col-md-8">
      <h5 class="mb-3">Monthly Summary</h5>
      <div class="row">
        ${monthlyCards || '<p class="text-muted">No data available</p>'}
      </div>
    </div>

    <div class="col-md-4">
      <h5 class="mb-3">Category Totals</h5>
      <ul class="list-group shadow-sm">
        ${categoryList || '<li class="list-group-item">No data</li>'}
      </ul>
    </div>
  </div>

    <!-- EXPORT -->
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <h5 class="mb-3">Download Monthly Report</h5>

      <form class="row g-3" onsubmit="return false;">
        <div class="col-md-4">
          <input type="month" id="exportMonth" class="form-control" required>
        </div>

        <div class="col-md-4 d-grid">
          <button class="btn btn-success" onclick="downloadExcel()">
            ⬇ Excel
          </button>
        </div>

        <div class="col-md-4 d-grid">
          <button class="btn btn-danger" onclick="downloadPDF()">
            ⬇ PDF
          </button>
        </div>
      </form>
    </div>
  </div>


 
<script>
  function downloadExcel() {
    const month = document.getElementById('exportMonth').value;
    if (!month) {
      alert('Select month');
      return;
    }
    window.location = "/admin/expenses/export/excel?month=" + month;
  }

  function downloadPDF() {
    const month = document.getElementById('exportMonth').value;
    if (!month) {
      alert('Select month');
      return;
    }
    window.location = "/admin/expenses/export/pdf?month=" + month;
  }
</script>
  </body>
</html>
  `);
});

// ==================== POST /admin/expenses ====================
app.post('/admin/expenses', isAuthenticated, isAdmin, async (req, res) => {
  const { title, category, amount, expense_date } = req.body;

  await pool.query(
    `
    INSERT INTO expenses (title, category, amount, expense_date)
    VALUES ($1, $2, $3, $4::DATE)
    `,
    [
      title,
      category,
      amount,
      expense_date || new Date().toISOString().slice(0, 10)
    ]
  );

  res.redirect('/admin/expenses');
});

// ==================== DELETE /admin/expenses/:id ====================
app.post('/admin/expenses/delete/:id', isAuthenticated, isAdmin, async (req, res) => {
  await pool.query(
    'DELETE FROM expenses WHERE id = $1',
    [req.params.id]
  );

  res.redirect('/admin/expenses');
});

// ADMIN EXPENSES/EXPORT/EXCEL
const ExcelJS = require('exceljs');

app.get('/admin/expenses/export/excel', isAuthenticated, isAdmin, async (req, res) => {
  const { month } = req.query; // YYYY-MM

  const result = await pool.query(
    `
    SELECT title, category, amount, expense_date
    FROM expenses
    WHERE TO_CHAR(expense_date, 'YYYY-MM') = $1
    ORDER BY expense_date ASC
    `,
    [month]
  );


  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet(`Expenses ${month}`);

  sheet.columns = [
    { header: 'Title', key: 'title', width: 25 },
    { header: 'Category', key: 'category', width: 15 },
    { header: 'Amount (KES)', key: 'amount', width: 15 },
    { header: 'Date', key: 'expense_date', width: 15 }
  ];

  result.rows.forEach(row => {
    sheet.addRow({
      title: row.title,
      category: row.category,
      amount: row.amount,
      expense_date: row.expense_date.toISOString().split('T')[0]
    });
  });

  sheet.getRow(1).font = { bold: true };

  res.setHeader(
    'Content-Disposition',
    `attachment; filename=expenses-${month}.xlsx`
  );

  await workbook.xlsx.write(res);
  res.end();
});

//ADMIN/EXPENSES/EXPORT/PDF
const PDFDocument = require('pdfkit');

app.get('/admin/expenses/export/pdf', isAuthenticated, isAdmin, async (req, res) => {
  const { month } = req.query;

  // Fetch expenses
  const result = await pool.query(
    `
    SELECT title, category, amount, expense_date
    FROM expenses
    WHERE TO_CHAR(expense_date, 'YYYY-MM') = $1
    ORDER BY expense_date ASC
    `,
    [month]
  );

  // Calculate category totals
  const categoryTotals = {};
  result.rows.forEach(exp => {
    if (!categoryTotals[exp.category]) categoryTotals[exp.category] = 0;
    categoryTotals[exp.category] += Number(exp.amount);
  });

  const doc = new PDFDocument({ margin: 40, size: 'A4' });

  res.setHeader(
    'Content-Disposition',
    `attachment; filename=expenses-${month}.pdf`
  );
  res.setHeader('Content-Type', 'application/pdf');

  doc.pipe(res);

  /* ================= HEADER ================= */
  doc
    .fontSize(20)
    .font('Helvetica-Bold')
    .text('Monthly Expense Report', { align: 'center' });

  doc
    .moveDown(0.5)
    .fontSize(11)
    .font('Helvetica')
    .fillColor('gray')
    .text(`Month: ${month} | Generated: ${new Date().toLocaleDateString()}`, {
      align: 'center'
    });

  doc.moveDown(1.5);
  doc.fillColor('black');

  /* ================= TABLE HEADER ================= */
  const startX = doc.x;
  let y = doc.y;

  const col = {
    date: startX,
    title: startX + 80,
    category: startX + 280,
    amount: startX + 390
  };

  doc.font('Helvetica-Bold').fontSize(11);
  doc.text('Date', col.date, y);
  doc.text('Title', col.title, y);
  doc.text('Category', col.category, y);
  doc.text('Amount (KES)', col.amount, y, { align: 'right' });

  y += 18;
  doc.moveTo(startX, y).lineTo(550, y).stroke();
  y += 10;

  /* ================= TABLE ROWS ================= */
  doc.font('Helvetica').fontSize(10);

  let total = 0;

  for (const exp of result.rows) {
    if (y > 750) {
      doc.addPage();
      y = 50;
    }

    total += Number(exp.amount);

    doc.text(exp.expense_date.toISOString().split('T')[0], col.date, y);
    doc.text(exp.title, col.title, y, { width: 180 });
    doc.text(exp.category, col.category, y);
    doc.text(Number(exp.amount).toLocaleString(), col.amount, y, { align: 'right' });

    y += 18;
  }

  /* ================= CATEGORY TOTALS ================= */
  y += 15;
  doc.font('Helvetica-Bold').fontSize(12).text('Category Totals:', startX, y);
  y += 18;

  doc.font('Helvetica').fontSize(11);
  for (const [category, amount] of Object.entries(categoryTotals)) {
    doc.text(`${category}: KES ${amount.toLocaleString()}`, startX + 10, y);
    y += 16;
  }

  /* ================= GRAND TOTAL ================= */
  y += 10;
  doc.moveTo(startX, y).lineTo(550, y).stroke();
  y += 10;
  doc.font('Helvetica-Bold').fontSize(12);
  doc.text(`Total: KES ${total.toLocaleString()}`, col.amount, y, { align: 'right' });

  doc.end();
});

/* 🔹 Step 3: Stripe Checkout (Dynamic Amount) */
app.post('/pay/card', isAuthenticated, async (req, res) => {
  const { course_id, course_name, amount } = req.body;
  const userId = req.user.id; // from Passport

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      customer_email: req.user.email,

      metadata: {
        user_id: userId.toString(),
        course_id: course_id.toString()
      },

      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: course_name },
            unit_amount: parseInt(amount) * 100,
          },
          quantity: 1,
        },
      ],

      success_url:
        process.env.STRIPE_SUCCESS_URL +
        '?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: process.env.STRIPE_CANCEL_URL,
    });

    res.redirect(session.url);
  } catch (err) {
    console.error(err);
    res.status(500).send('Payment failed');
  }
});


/* 🔹 Payment Success & Cancel Pages */
app.get('/payment-success', isAuthenticated, (req, res) => {
  res.send(`
    <h2>Payment Successful 🎉</h2>
    <p>You are now enrolled.</p>
    <a href="/my-courses">My Courses</a>
  `);
});

app.get('/payment-cancel', isAuthenticated, (req, res) => {
  res.send(`
    <h2>Payment Cancelled</h2>
    <a href="/courses">Try again</a>
  `);
});


//SALES TRACKING
app.get(
  '/admin/sales',
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    try {
      /* 🔹 Total Sales */
      const totalSalesResult = await pool.query(`
        SELECT
          COALESCE(SUM(amount), 0) AS total
        FROM payments
        WHERE status = 'paid'
      `);

      const totalSales = (totalSalesResult.rows[0].total / 100).toFixed(2);

      /* 🔹 Sales Per Course */
      const perCourseResult = await pool.query(`
        SELECT
          c.id,
          c.name,
          COUNT(p.id) AS sales_count,
          COALESCE(SUM(p.amount), 0) AS total_amount
        FROM courses c
        LEFT JOIN payments p
          ON p.course_id = c.id
          AND p.status = 'paid'
        GROUP BY c.id
        ORDER BY total_amount DESC
      `);

      const rows = perCourseResult.rows.map(course => `
        <tr>
          <td>${course.id}</td>
          <td>${course.name}</td>
          <td>${course.sales_count}</td>
          <td>$${(course.total_amount / 100).toFixed(2)}</td>
        </tr>
      `).join('');

      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Sales Dashboard</title>
          <link
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
            rel="stylesheet">
        </head>
        <body class="container mt-4">

          <h2 class="mb-3">📊 Sales Dashboard</h2>

          <div class="alert alert-success">
            <strong>Total Revenue:</strong> $${totalSales}
          </div>

          <table class="table table-bordered table-striped">
            <thead class="table-dark">
              <tr>
                <th>Course ID</th>
                <th>Course Name</th>
                <th>Sales</th>
                <th>Total Revenue</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>

          <a href="/admin" class="btn btn-secondary mt-3">← Back to Admin</a>

        </body>
        </html>
      `);

    } catch (err) {
      console.error(err);
      res.status(500).send('Failed to load sales data');
    }
  }
);



/* 🔹 Routes */
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) =>
  res.sendFile(path.join(__dirname, 'pages', 'login.html'))
);


app.get('/register', (req, res) =>
  res.sendFile(path.join(__dirname, 'pages', 'register.html'))
);

/* 🔹 Google Auth */
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/home')
);

/* 🔹 Register */
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  const existing = await pool.query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );
  if (existing.rows.length > 0) return res.send('Email already registered');

  const hashed = await bcrypt.hash(password, 10);
  await pool.query(
    'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
    [username, email, hashed]
  );

  res.redirect('/login');
});

/* 🔹 Login */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );
  if (result.rows.length === 0) return res.send('User not found');

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.send('Incorrect password');

  req.login(user, err => {
    if (err) return res.send('Login error');
    res.redirect('/home');
  });
});

/* 🔹 Forgot Password */
async function sendResetEmail(email, link) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: `"My Website" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Reset Your Password',
    html: `
      <p>You requested a password reset.</p>
      <p><a href="${link}">Click here</a></p>
      <p>This link expires in 15 minutes.</p>
    `,
  });
}

app.get('/forgot-password', (req, res) =>
  res.sendFile(path.join(__dirname, 'pages', 'forgot-password.html'))
);

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  const result = await pool.query(
    'SELECT id FROM users WHERE email = $1',
    [email]
  );

  if (result.rows.length === 0)
    return res.send('If the email exists, a reset link has been sent.');

  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  const expiry = new Date(Date.now() + 15 * 60 * 1000);

  await pool.query(
    `UPDATE users
     SET reset_token = $1, reset_token_expiry = $2
     WHERE email = $3`,
    [hashedToken, expiry, email]
  );

  const resetLink = `http://localhost:${PORT}/reset-password/${token}`;
  await sendResetEmail(email, resetLink);

  res.send('If the email exists, a reset link has been sent.');
});

app.get('/reset-password/:token', (req, res) =>
  res.sendFile(path.join(__dirname, 'pages', 'reset-password.html'))
);

app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirm } = req.body;

  if (password !== confirm) return res.send('Passwords do not match.');

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const result = await pool.query(
    `SELECT id FROM users
     WHERE reset_token = $1 AND reset_token_expiry > NOW()`,
    [hashedToken]
  );

  if (result.rows.length === 0) return res.send('Invalid or expired token.');

  const hashedPassword = await bcrypt.hash(password, 10);

  await pool.query(
    `UPDATE users
     SET password = $1, reset_token = NULL, reset_token_expiry = NULL
     WHERE id = $2`,
    [hashedPassword, result.rows[0].id]
  );

  res.send('Password reset successful.');
});

/* 🔹 Protected Pages */
[
  'home',
  //'hobbies',
  //'certifications',
  'Contact',
  //'course',
  //'skill',
  //'books',
  //'work',
].forEach(page => {
  app.get(`/${page}`, isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, 'pages', `${page}.html`))
  );
});

// DYNAMIC HOBBIES PAGE
app.get('/hobbies', isAuthenticated, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM profile_items WHERE type = 'hobby' ORDER BY created_at DESC"
  );

  const pageTitle = 'My Hobbies';

  const html = result.rows.map(item => {
    // Use file_path first (new uploads), fallback to image_url (old)
    const fileUrl =
      item.file_path && item.file_path.trim()
        ? item.file_path.trim()
        : (item.image_url && item.image_url.trim() ? item.image_url.trim() : null);

    const isPdf = fileUrl && fileUrl.toLowerCase().endsWith('.pdf');

    return `
      <div class="col-md-4 col-sm-6 mb-4">
        <div class="card h-100 shadow-sm border-0">

          <!-- Title -->
          <div class="card-header bg-white text-center fw-semibold">
            ${item.title}
          </div>

          <!-- File Preview -->
          <div class="card-body text-center">
            ${
              isPdf
                ? `
                  <embed src="${fileUrl}" type="application/pdf" width="100%" height="220px" />
                  <a href="${fileUrl}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">
                    View / Download PDF
                  </a>
                `
                : `
                  <img
                    src="${fileUrl || '/images/default-item.jpg'}"
                    class="img-fluid rounded"
                    style="object-fit:cover; height:220px; width:100%;"
                    alt="${item.title}"
                  />
                `
            }

            <!-- Description -->
            <p class="card-text text-muted mt-3">
              ${item.description || ''}
            </p>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>${pageTitle}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />

    <!-- Shared + Page CSS -->
    <link rel="stylesheet" href="/css/styles.css">
    <link rel="stylesheet" href="/css/hobbies.css">
  </head>
  <body>
    <div class="container py-5">
      <h2 class="mb-5 text-center fw-bold">
        ${pageTitle.toUpperCase()}
      </h2>

      <div class="row">
        ${html || '<p class="text-muted text-center">No hobbies yet.</p>'}
      </div>
    </div>
  </body>
  </html>
  `);
});


// DYNAMIC BOOKS PAGE
app.get('/books', isAuthenticated, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM profile_items WHERE type = 'book' ORDER BY created_at DESC"
  );

  const pageTitle = 'My Books';

  const html = result.rows.map(item => {
    // Use file_path first (new uploads), fallback to image_url (old)
    const fileUrl =
      item.file_path && item.file_path.trim()
        ? item.file_path.trim()
        : (item.image_url && item.image_url.trim() ? item.image_url.trim() : null);

    const isPdf = fileUrl && fileUrl.toLowerCase().endsWith('.pdf');

    return `
      <div class="col-md-4 col-sm-6 mb-4">
        <div class="card h-100 shadow-sm border-0">

          <!-- Title -->
          <div class="card-header bg-white text-center fw-semibold">
            ${item.title}
          </div>

          <!-- File Preview -->
          <div class="card-body text-center">
            ${
              isPdf
                ? `
                  <embed src="${fileUrl}" type="application/pdf" width="100%" height="220px" />
                  <a href="${fileUrl}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">
                    View / Download PDF
                  </a>
                `
                : `
                  <img
                    src="${fileUrl || '/images/default-item.jpg'}"
                    class="img-fluid rounded"
                    style="object-fit:cover; height:220px; width:100%;"
                    alt="${item.title}"
                  />
                `
            }

            <!-- Description -->
            <p class="card-text text-muted mt-3">
              ${item.description || ''}
            </p>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>${pageTitle}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />

    <!-- Shared + Page CSS -->
    <link rel="stylesheet" href="/css/styles.css">
    <link rel="stylesheet" href="/css/books.css">
  </head>
  <body>
    <div class="container py-5">
      <h2 class="mb-5 text-center fw-bold">
        ${pageTitle.toUpperCase()}
      </h2>

      <div class="row">
        ${html || '<p class="text-muted text-center">No books yet.</p>'}
      </div>
    </div>
  </body>
  </html>
  `);
});



// DYNAMIC  SKILLS PAGE
app.get('/skills', isAuthenticated, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM profile_items WHERE type = 'skill' ORDER BY created_at DESC"
  );

  const pageTitle = 'My Skills';

  const html = result.rows.map(item => {
    // Use file_path first (new uploads), fallback to image_url (old)
    const fileUrl =
      item.file_path && item.file_path.trim()
        ? item.file_path.trim()
        : (item.image_url && item.image_url.trim() ? item.image_url.trim() : null);

    const isPdf = fileUrl && fileUrl.toLowerCase().endsWith('.pdf');
    const rating = item.rating || 0;
    const width = rating * 20; // Each star = 20%

    // Choose progress bar color
    let colorClass = 'progress-red';
    if (rating === 2) colorClass = 'progress-orange';
    else if (rating === 3) colorClass = 'progress-yellow';
    else if (rating === 4) colorClass = 'progress-lime';
    else if (rating === 5) colorClass = 'progress-green';

    return `
      <div class="col-md-4 col-sm-6 mb-4">
        <div class="card h-100 shadow-sm border-0">

          <!-- Title -->
          <div class="card-header bg-white text-center fw-semibold">
            ${item.title}
          </div>

          <!-- File Preview -->
          <div class="card-body text-center">
            ${
              isPdf
                ? `
                  <embed src="${fileUrl}" type="application/pdf" width="100%" height="220px" />
                  <a href="${fileUrl}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">
                    View / Download PDF
                  </a>
                `
                : `
                  <img
                    src="${fileUrl || '/images/default-item.jpg'}"
                    class="img-fluid rounded"
                    style="object-fit:cover; height:220px; width:100%;"
                    alt="${item.title}"
                  />
                `
            }

            <!-- Description -->
            <p class="card-text text-muted mt-3">
              ${item.description || ''}
            </p>

            <!-- Skill Progress Bar -->
            <div class="progress mt-2" style="height: 20px; border-radius:8px;">
              <div class="progress-bar ${colorClass}" style="width:${width}%; line-height:20px;">
                ${rating} / 5
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>${pageTitle}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />

    <!-- Shared + Page CSS -->
    <link rel="stylesheet" href="/css/styles.css">
    <link rel="stylesheet" href="/css/skills.css">

    <style>
      /* Progress bar colors */
      .progress-red { background-color: #dc3545; }       /* 1 star */
      .progress-orange { background-color: #fd7e14; }    /* 2 stars */
      .progress-yellow { background-color: #ffc107; color:#000; }  /* 3 stars */
      .progress-lime { background-color: #8bc34a; }      /* 4 stars */
      .progress-green { background-color: #28a745; }     /* 5 stars */
    </style>
  </head>
  <body>
    <div class="container py-5">
      <h2 class="mb-5 text-center fw-bold">
        ${pageTitle.toUpperCase()}
      </h2>

      <div class="row">
        ${html || '<p class="text-muted text-center">No skills yet.</p>'}
      </div>
    </div>
  </body>
  </html>
  `);
});

// DYNAMIC WORK PAGE
app.get('/work', isAuthenticated, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM profile_items WHERE type = 'work' ORDER BY created_at DESC"
  );

  const pageTitle = 'My Work Experience';

  const html = result.rows.map(item => {
    // Use file_path first (new uploads), fallback to image_url (old)
    const fileUrl =
      item.file_path && item.file_path.trim()
        ? item.file_path.trim()
        : (item.image_url && item.image_url.trim() ? item.image_url.trim() : null);

    const isPdf = fileUrl && fileUrl.toLowerCase().endsWith('.pdf');

    return `
      <div class="col-md-4 col-sm-6 mb-4">
        <div class="card h-100 shadow-sm border-0">

          <!-- Title -->
          <div class="card-header bg-white text-center fw-semibold">
            ${item.title}
          </div>

          <!-- File Preview -->
          <div class="card-body text-center">
            ${
              isPdf
                ? `
                  <embed src="${fileUrl}" type="application/pdf" width="100%" height="220px" />
                  <a href="${fileUrl}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">
                    View / Download PDF
                  </a>
                `
                : `
                  <img
                    src="${fileUrl || '/images/default-item.jpg'}"
                    class="img-fluid rounded"
                    style="object-fit:cover; height:220px; width:100%;"
                    alt="${item.title}"
                  />
                `
            }

            <!-- Description -->
            <p class="card-text text-muted mt-3">
              ${item.description || ''}
            </p>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>${pageTitle}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap -->
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />

    <!-- Shared + Page CSS -->
    <link rel="stylesheet" href="/css/styles.css">
    <link rel="stylesheet" href="/css/work.css">
  </head>
  <body>
    <div class="container py-5">
      <h2 class="mb-5 text-center fw-bold">
        ${pageTitle.toUpperCase()}
      </h2>

      <div class="row">
        ${html || '<p class="text-muted text-center">No work experience yet.</p>'}
      </div>
    </div>
  </body>
  </html>
  `);
});

// DYNAMIC CERTIFICATION PAGE
app.get('/certifications', isAuthenticated, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM profile_items WHERE type = 'certification' ORDER BY created_at DESC"
  );

  const pageTitle = 'My Certifications';

  const html = result.rows.map(item => {
    // Use file_path first, fallback to old image_url
    const fileUrl = (item.file_path && item.file_path.trim())
      ? item.file_path.trim()
      : (item.image_url && item.image_url.trim() ? item.image_url.trim() : null);

    const isPdf = fileUrl && fileUrl.toLowerCase().endsWith('.pdf');

    return `
      <div class="col-md-4 col-sm-6 mb-4">
        <div class="card h-100 shadow-sm border-0">

          <!-- Title -->
          <div class="card-header bg-white text-center fw-semibold">
            ${item.title}
          </div>

          <!-- File Preview -->
          <div class="card-body text-center">
            ${
              isPdf
                ? `
                  <embed
                    src="${fileUrl}"
                    type="application/pdf"
                    width="100%"
                    height="220px"
                  />
                  <a href="${fileUrl}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">
                    View
                  </a>
                `
                : `
                  <img
                    src="${fileUrl || '/images/default-item.jpg'}"
                    class="img-fluid rounded"
                    style="object-fit:cover; height:220px; width:100%;"
                    alt="${item.title}"
                  />
                `
            }

            <!-- Description -->
            <p class="card-text text-muted mt-3">
              ${item.description || ''}
            </p>
          </div>
        </div>
      </div>
    `;
  }).join('');

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>${pageTitle}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <!-- Bootstrap -->
      <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
      />

      <!-- Shared + Page CSS -->
      <link rel="stylesheet" href="/css/styles.css">
    </head>
    <body>
      <div class="container py-5">
        <h2 class="mb-5 text-center fw-bold">
          ${pageTitle.toUpperCase()}
        </h2>

        <div class="row">
          ${html || '<p class="text-muted text-center">No certifications yet.</p>'}
        </div>
      </div>
    </body>
    </html>
  `);
});

/* 🔹 Dynamic Courses Page (Fully Responsive) */
app.get('/courses', isAuthenticated, async (req, res) => {
  try {
   const result = await pool.query(`
  SELECT
    c.id,
    c.name,
    c.description,
    c.price,
    c.image_url,
    cat.name AS category
  FROM courses c
  JOIN categories cat ON cat.id = c.category_id
  ORDER BY cat.name, c.name
`);

// GROUP BY CATEGORY
const grouped = {};

result.rows.forEach(course => {
  if (!grouped[course.category]) {
    grouped[course.category] = [];
  }
  grouped[course.category].push(course);
});

// BUILD HTML
let content = '';

for (const category in grouped) {
  const cards = grouped[category].map(course => `
    <div class="col-12 col-md-6 col-lg-4 mb-4">
      <div class="card h-100 shadow-sm">
        <img 
  src="${course.image_url?.trim() || '/images/default-course.jpg'}"
  class="card-img-top img-fluid"
  alt="${course.name}"
>

        <div class="card-body d-flex flex-column">
          <h5>${course.name}</h5>
          <p>${course.description}</p>
 <a href="/payment?course_id=${course.id}" class="btn btn-success mt-auto">
  Enroll
</a>


           
          </a>
        </div>
      </div>
    </div>
  `).join('');

  content += `
    <h3 class="mt-5 mb-3 text-primary text-center">${category}</h3>
    <div class="row">
      ${cards}
    </div>
  `;
}

   
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Courses</title>
        <link rel="stylesheet" href="/css/styles.css">
        <link rel="stylesheet" href="/css/courses.css">
        <link rel="icon" href="F.jpg">
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
        >
      </head>
      <body>
    
        <hr>
        <h3 class="page-title text-center mb-4">Courses</h3>

        <section class="container">
          <div class="row">
           ${content}

          </div>
        </section>
        

        <hr>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

/* 🔹 My Courses Page */
app.get('/my-courses', isAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT
        c.id,
        c.name,
        c.description,
        c.image_url,
        c.price,
        e.enrolled_at
      FROM enrollments e
      JOIN courses c ON c.id = e.course_id
      WHERE e.user_id = $1
      ORDER BY e.enrolled_at DESC
      `,
      [userId]
    );

    const courses = result.rows;

    if (courses.length === 0) {
      return res.send(`
        <h2>You are not enrolled in any courses yet.</h2>
        <a href="/courses">Browse Courses</a>
      `);
    }

    const courseCards = courses.map(course => `
      <div class="col-12 col-md-6 col-lg-4 mb-4">
        <div class="card h-100 shadow-sm">
         <img 
  src="${course.image_url?.trim() || '/images/default-course.jpg'}"
  class="card-img-top"
  alt="${course.name}">

          <div class="card-body d-flex flex-column">
            <h5 class="card-title">${course.name}</h5>
            <p class="card-text">${course.description}</p>
            <a href="/course/${course.id}" class="btn btn-primary mt-auto">
              ▶ Access Course
            </a>
          </div>
        </div>
      </div>
    `).join('');

    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My Courses</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <!-- Bootstrap CSS -->
  <link
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
    rel="stylesheet"
  >

  <link rel="stylesheet" href="/css/styles.css">
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
  <div class="container-fluid px-4">
    <a class="navbar-brand" href="/home"></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
      aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item"><a class="nav-link" href="/home">Home</a></li>
        <li class="nav-item"><a class="nav-link" href="/hobbies">My Hobbies</a></li>
        <li class="nav-item"><a class="nav-link" href="/books">Books & Teaching</a></li>
        <li class="nav-item"><a class="nav-link" href="/work">Work & Experience</a></li>
        <li class="nav-item"><a class="nav-link" href="/skills">My Skills</a></li>
        <li class="nav-item"><a class="nav-link" href="/certifications">Certifications</a></li>

        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
            Courses
          </a>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="/courses">View Courses</a></li>
            <li><a class="dropdown-item" href="/my-courses">My Courses</a></li>
            <li><a class="dropdown-item" href="/admin">Admin Dashboard</a></li>
            
          </ul>
        </li>

        <li class="nav-item"><a class="nav-link" href="/contact">Contact Us</a></li>
        <li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li>
      </ul>
    </div>
  </div>
</nav>


<!-- ✅ Page Content -->
<div class="container my-5">

  <h2 class="text-center mb-4">🎓 My Courses</h2>

  <div class="row g-4">
    ${courseCards}
  </div>

  <div class="text-center mt-5">
    <a href="/courses" class="btn btn-outline-primary">
      ➕ Enroll in more courses
    </a>
  </div>

</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


/* 🔹 Logout */
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

/* 🔹 Start server */

console.log("DB MODE:", process.env.DATABASE_URL ? "Render DB" : "Local DB");

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

