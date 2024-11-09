import express from 'express';
import * as dotenv from 'dotenv';
import pg from 'pg';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import { rateLimit } from 'express-rate-limit';

dotenv.config();

// defined config params
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL;
const PORT =
  EXTERNAL_URL && process.env.PORT ? parseInt(process.env.PORT) : 3000;
const SALT_ROUNDS = Number(process.env.SALT_ROUNDS)
  ? Number(process.env.SALT_ROUNDS)
  : 12;

const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  limit: 3, // Limit each IP to 3 requests per `window` (here, per 5 minutes).
  standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
  skip: (req, res) => req.body?.allowBadAuth,
});

// #region CONNECT TO DB
const { Pool } = pg;
const pool = new Pool({
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  pplication_name: 'Learn Web Safety',
  ssl: {
    rejectUnauthorized: false,
    require: process.env.PGSSLMODE,
  },
});

pool
  .connect()
  .then(() => console.info('Connected to DB.'))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
// #endregion

const app = express();

// set template views
app.set('view engine', 'ejs');
app.set(
  'views',
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'src', 'views')
);

// define middlware
app.use(cors());
app.use(
  express.static(
    path.join(path.dirname(fileURLToPath(import.meta.url)), 'public')
  )
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// routes
app.get('/', (req, res) => {
  res.redirect('/sql-injection');
});

// #region SQL INJECTION
app.get('/sql-injection', (req, res) => {
  res.render('layout', {
    title: 'SQL Injection Demo',
    navbar: 'navbar.ejs',
    body: 'sqlInjection.ejs',
    error: undefined,
    result: undefined,
  });
});

app.post('/sql-injection', async (req, res) => {
  try {
    const { username, password, allowInjection } = req.body;

    let query;

    if (allowInjection) {
      query = `SELECT * FROM APP_USER WHERE NAME = '${username}' AND PASSWORD = '${password}'`;
    } else {
      query = {
        text: 'SELECT * FROM APP_USER WHERE NAME = $1 AND PASSWORD = $2',
        values: [username, password],
      };
    }

    const response = await pool.query(query);

    res.render('layout', {
      title: 'SQL Injection Demo',
      navbar: 'navbar.ejs',
      body: 'sqlInjection.ejs',
      error: undefined,
      result: response.rows,
    });
  } catch (error) {
    console.error(error);
    res.render('layout', {
      title: 'SQL Injection Demo',
      navbar: 'navbar.ejs',
      body: 'sqlInjection.ejs',
      error: error.message,
      result: undefined,
    });
  }
});

// #endregion SQL INJECTION

// #region BAD AUTH
app.get('/bad-auth', (req, res) => {
  res.render('layout', {
    title: 'Bad Authentication Demo',
    navbar: 'navbar.ejs',
    body: 'badAuth.ejs',
    error: undefined,
    result: undefined,
  });
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password, allowBadAuth } = req.body;

    let storedPassword;

    if (allowBadAuth) {
      storedPassword = password;
    } else {
      if (password.length < 8) {
        throw new Error(
          'Password must be at least 8 charachters long, because allowBadAuth is disabled.'
        );
      }

      storedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    }

    const isThereSameUserNameQuery = {
      text: 'SELECT * FROM APP_USER_BAD_AUTH WHERE NAME = $1;',
      values: [username],
    };

    const responseCheckUsername = await pool.query(isThereSameUserNameQuery);

    if (responseCheckUsername.rows.length) {
      if (allowBadAuth) {
        throw new Error('User with this name alredy exists.');
      } else {
        throw new Error('Error trying to register you. Try again.');
      }
    }

    const registerUserQuery = {
      text: 'INSERT INTO APP_USER_BAD_AUTH (NAME, PASSWORD) VALUES ($1, $2) RETURNING USER_ID, NAME, PASSWORD;',
      values: [username, storedPassword],
    };

    const response = await pool.query(registerUserQuery);
    res.render('layout', {
      title: 'Bad Authentication Demo',
      navbar: 'navbar.ejs',
      body: 'badAuth.ejs',
      error: undefined,
      result: response.rows,
    });
  } catch (error) {
    console.error(error);
    res.render('layout', {
      title: 'Bad Authentication Demo',
      navbar: 'navbar.ejs',
      body: 'badAuth.ejs',
      error: error.message,
      result: undefined,
    });
  }
});

app.post('/login', limiter, async (req, res) => {
  try {
    const { username, password, allowBadAuth } = req.body;

    if (!allowBadAuth) {
      if (password.length < 8) {
        throw new Error(
          'Password must be at least 8 charachters long, because allowBadAuth is disabled.'
        );
      }
    }

    const findUserQuery = {
      text: 'SELECT * FROM APP_USER_BAD_AUTH WHERE NAME = $1;',
      values: [username],
    };

    const response = await pool.query(findUserQuery);

    if (response.rows.length === 0) {
      if (allowBadAuth) {
        throw new Error('User with this name does not exist.');
      } else {
        throw new Error('Wrong credentials.');
      }
    }

    if (allowBadAuth) {
      if (password !== response.rows[0].password) {
        throw new Error(`Wrong password for this ${username}`);
      }
    } else {
      const isRightPassword = await bcrypt.compare(
        password,
        response.rows[0].password
      );
      if (!isRightPassword) {
        throw new Error('Wrong credentials.');
      }
    }

    res.render('layout', {
      title: 'Bad Authentication Demo',
      navbar: 'navbar.ejs',
      body: 'badAuth.ejs',
      error: undefined,
      result: response.rows,
    });
  } catch (error) {
    console.error(error);
    res.render('layout', {
      title: 'Bad Authentication Demo',
      navbar: 'navbar.ejs',
      body: 'badAuth.ejs',
      error: error.message,
      result: undefined,
    });
  }
});
// #endregion BAD AUTH

// 404 routes
app.use((req, res) => {
  res.status(404).render('layout', {
    title: 'Page Not Found',
    navbar: 'navbar.ejs',
    body: '404.ejs',
  });
});

// start the server
if (EXTERNAL_URL) {
  const hostname = '0.0.0.0';
  app.listen(PORT, hostname, () => {
    console.log(`Server locally running at http://${hostname}:${PORT}/ and from
  outside on ${EXTERNAL_URL}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}/`);
  });
}
