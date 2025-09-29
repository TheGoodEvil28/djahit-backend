const express = require('express');
const { pool } = require("./db");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { body, param, query, validationResult } = require('express-validator');
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const xss = require('xss');
const morgan = require('morgan');



// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(compression());
app.use(cors({
  origin: '*',                 // allow all origins
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Requested-With'],
  credentials: true,           // allow cookies/auth headers if needed
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests
// app.options('*', cors());

// Your existing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));
if (process.env.NODE_ENV === 'production') {
  // Force HTTPS
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      return res.redirect(`https://${req.header('host')}${req.url}`);
    }
    next();
  });

  // Additional security headers
  app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Stricter rate limiting for production
  const productionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50, // Reduced from 100
    message: {
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please try again later.'
      }
    }
  });
  app.use('/api/', productionLimiter);
}
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required');
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be at least 32 characters long');
  process.exit(1);
}
const PORT = process.env.PORT;

const getJakartaTime = () => {
  return new Date().toLocaleString('sv-SE', {
    timeZone: 'Asia/Jakarta'
  });
};

const getJakartaTimeISO = () => {
  return new Date().toLocaleString('en-CA', {
    timeZone: 'Asia/Jakarta',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).replace(', ', 'T') + '+07:00';
};
const originalQuery = pool.query.bind(pool);
pool.query = function(text, params, callback) {
  if (typeof text === 'string') {
    text = text.replace(/NOW\(\)/g, `'${getJakartaTime()}'`);
  }
  return originalQuery(text, params, callback);
};
// ============= MIDDLEWARE =============

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Access token is required'
      }
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Invalid or expired token'
        }
      });
    }
    req.user = user;
    next();
  });
};
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: process.env.NODE_ENV === 'production' ? '15m' : '1h' }
  );
  
  const refreshToken = jwt.sign(
    { id: user.id, email: user.email, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
};
const validateRepairRequestCreate = [
  body('original_img_url')
    .isURL({ require_protocol: true, protocols: ['http', 'https'] })
    .isLength({ max: 500 })
    .withMessage('Valid image URL is required (max 500 characters)'),
  body('img_filename')
    .optional()
    .isLength({ max: 255 })
    .matches(/^[a-zA-Z0-9._-]+$/)
    .withMessage('Invalid filename format'),
  body('file_size')
    .optional()
    .isInt({ min: 0, max: 50000000 }) // 50MB max
    .withMessage('File size must be between 0 and 50MB'),
  body('mime_type')
    .optional()
    .matches(/^image\/(jpeg|jpg|png|gif|webp)$/)
    .withMessage('Invalid image mime type'),
  body('ai_scan_desc')
    .optional()
    .isLength({ max: 2000 })
    .withMessage('AI scan description too long'),
  body('damage_type')
    .isIn(['Sobek', 'Resleting Rusak', 'Kancing Hilang', 'Lainnya'])
    .withMessage('Invalid damage type'),
  body('damage_type_other_desc')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Damage description too long'),
  body('clothing_type')
    .isIn(['Baju', 'Celana', 'Outer', 'Lainnya'])
    .withMessage('Invalid clothing type'),
  body('clothing_type_other_desc')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Clothing description too long'),
  body('clothing_size')
    .optional()
    .isIn(['XS', 'S', 'M', 'L', 'XL', 'XXL'])
    .withMessage('Invalid clothing size'),
  body('pickup_location')
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Pickup location must be 5-500 characters'),
  body('pickup_phone')
    .matches(/^(\+62|62|0)[0-9]{9,13}$/)
    .withMessage('Invalid Indonesian phone number'),
  body('thread_color_pref')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Thread color preference too long'),
  body('estimated_cost')
    .optional()
    .isDecimal({ decimal_digits: '0,2' })
    .custom(value => {
      if (parseFloat(value) < 0 || parseFloat(value) > 99999999.99) {
        throw new Error('Invalid cost range');
      }
      return true;
    }),
    body('status')
    .isIn(['Pending','Order Diterima','Sedang Dijahit','Dalam Pengiriman','Selesai'])
    .withMessage('Wrong status!')
];

const validateRepairRequestUpdate = [
  body('ai_scan_desc').optional().isLength({ max: 2000 }),
  body('damage_type').optional().isIn(['Sobek', 'Resleting Rusak', 'Kancing Hilang', 'Lainnya']),
  body('damage_type_other_desc').optional().isLength({ max: 500 }),
  body('clothing_type').optional().isIn(['Baju', 'Celana', 'Outer', 'Lainnya']),
  body('clothing_type_other_desc').optional().isLength({ max: 500 }),
  body('clothing_size').optional().isIn(['XS', 'S', 'M', 'L', 'XL', 'XXL','XXXL']),
  body('pickup_location').optional().trim().isLength({ min: 5, max: 500 }),
  body('thread_color_pref').optional().isLength({ max: 100 }),
  body('estimated_cost').optional().isDecimal({ decimal_digits: '0,2' }).custom(value => {
    if (parseFloat(value) < 0 || parseFloat(value) > 99999999.99) {
      throw new Error('Invalid cost range');
    }
    return true;
  }),
  body('status').optional().isIn(['Pending', 'Order Diterima','Sedang Dijahit','Dalam Pengiriman','Selesai'])
];

const validatePagination = [
  query('page').optional().isInt({ min: 1, max: 1000 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['Pending','Order Diterima','Sedang Dijahit','Dalam Pengiriman','Selesai'])
];

const validateId = [
  param('id').isInt({ min: 1 }).withMessage('Invalid ID')
];

// Check validation results
const checkValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        details: errors.array()
      }
    });
  }
  next();
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Server Error:', {
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : 'Hidden in production',
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().getJakartaTimeISO()
  });
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: isDevelopment ? err.message : 'An internal server error occurred',
      ...(isDevelopment && { stack: err.stack })
    }
  });
};

// ============= ROUTES =============

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    data: {
      status: 'healthy',
      timestamp: getJakartaTimeISO(),
      version: '1.0.0'
    }
  });
});

// ============= AUTH RESOURCES =============

// POST /api/auth/register - Register a new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const firstname = xss(req.body.firstname?.trim());
    const lastname = xss(req.body.lastname?.trim());
    const email = xss(req.body.email?.toLowerCase().trim());
    const password = req.body.password; 
    const phone = xss(req.body.phone?.trim());

    // Validation
    if (!firstname || !lastname || !email || !password || !phone) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'All fields are required',
          details: {
            required: ['firstname', 'lastname', 'email', 'password', 'phone']
          }
        }
      });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid email format'
        }
      });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'CONFLICT',
          message: 'User with this email already exists'
        }
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (firstname, lastname, email, password, phone, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING id, firstname, lastname, email, phone, created_at`,
      [firstname, lastname, email, hashedPassword, phone]
    );

    const newUser = result.rows[0];

    res.status(201).json({
      success: true,
      data: {
        user: {
          id: newUser.id,
          firstname: newUser.firstname,
          lastname: newUser.lastname,
          email: newUser.email,
          phone: newUser.phone,
          createdAt: newUser.created_at
        }
      },
      message: 'User registered successfully, please continue to log in'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to register user'
      }
    });
  }
});

// POST /api/auth/login - Authenticate user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Email and password are required'
        }
      });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, firstname, lastname, email, password, phone FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid credentials'
        }
      });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid credentials'
        }
      });
    }

    // Generate JWT token
    const tokens = generateTokens(user);


    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          firstname: user.firstname,
          lastname: user.lastname,
          email: user.email,
          phone: user.phone
        },
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        tokenType: 'Bearer'
      },
      message: 'Login successful'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to authenticate user'
      }
    });
  }
});

// POST /api/auth/logout - Logout user (stateless, just for client-side cleanup)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  // In a stateless JWT system, logout is handled client-side
  // But we can provide this endpoint for consistency
  res.json({
    success: true,
    message: 'Logout successful. Please remove the token from client storage.'
  });
});

// ============= USER RESOURCES =============

// GET /api/users/me - Get current user profile
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, firstname, lastname, email, phone, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'User not found'
        }
      });
    }

    const user = result.rows[0];

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          firstname: user.firstname,
          lastname: user.lastname,
          email: user.email,
          phone: user.phone,
          createdAt: user.created_at
        }
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to fetch user profile'
      }
    });
  }
});

// PUT /api/users/me - Update current user profile
app.put('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { firstname, lastname, phone } = req.body;
    const userId = req.user.id;

    // Build dynamic query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (firstname) {
      updates.push(`firstname = $${paramCount++}`);
      values.push(firstname);
    }
    if (lastname) {
      updates.push(`lastname = $${paramCount++}`);
      values.push(lastname);
    }
    if (phone) {
      updates.push(`phone = $${paramCount++}`);
      values.push(phone);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'No valid fields to update'
        }
      });
    }

    values.push(userId);

    const query = `
      UPDATE users 
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, firstname, lastname, email, phone
    `;

    const result = await pool.query(query, values);
    const updatedUser = result.rows[0];

    res.json({
      success: true,
      data: {
        user: {
          id: updatedUser.id,
          firstname: updatedUser.firstname,
          lastname: updatedUser.lastname,
          email: updatedUser.email,
          phone: updatedUser.phone,
        }
      },
      message: 'Profile updated successfully'
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to update user profile'
      }
    });
  }
});

// DELETE /api/users/me - Delete current user account
app.delete('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'User not found'
        }
      });
    }

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });

  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to delete account'
      }
    });
  }
});

// ============= ADMIN ROUTES (Optional) =============

// GET /api/users - Get all users (admin only)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // Add admin check here if needed
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT id, firstname, lastname, email, phone, created_at 
       FROM users 
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const totalUsers = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      success: true,
      data: {
        users: result.rows,
        pagination: {
          page,
          limit,
          totalUsers,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to fetch users'
      }
    });
  }
});

// ============= REPAIR REQUESTS RESOURCES =============

app.get('/api/repair-requests', 
  authenticateToken, 
  validatePagination, 
  checkValidation,
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Cap at 100
      const offset = (page - 1) * limit;
      const status = req.query.status;
      const userId = req.user.id;

      // Build query with proper parameterization
      let baseQuery = `
        SELECT 
          id, user_id, original_img_url, img_filename, file_size, mime_type,
          ai_scan_desc, damage_type, damage_type_other_desc, clothing_type,
          clothing_type_other_desc, clothing_size, pickup_location, pickup_phone,
          thread_color_pref, estimated_cost, status, created_at, updated_at
        FROM repair_requests 
        WHERE user_id = $1
      `;
      
      let countQuery = 'SELECT COUNT(*) FROM repair_requests WHERE user_id = $1';
      let queryParams = [userId];
      
      if (status) {
        baseQuery += ' AND status = $2';
        countQuery += ' AND status = $2';
        queryParams.push(status);
      }
      
      baseQuery += ' ORDER BY created_at DESC LIMIT $' + (queryParams.length + 1) + ' OFFSET $' + (queryParams.length + 2);
      queryParams.push(limit, offset);

      // Execute queries with transaction for consistency
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        
        const [result, countResult] = await Promise.all([
          client.query(baseQuery, queryParams),
          client.query(countQuery, queryParams.slice(0, status ? 2 : 1))
        ]);
        
        await client.query('COMMIT');
        
        const totalRequests = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalRequests / limit);

        res.json({
          success: true,
          data: {
            repair_requests: result.rows,
            pagination: {
              page,
              limit,
              totalRequests,
              totalPages,
              hasNextPage: page < totalPages,
              hasPrevPage: page > 1
            }
          }
        });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Get repair requests error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to fetch repair requests'
        }
      });
    }
  }
);

// GET /api/repair-requests/:id - Get specific repair request with proper authorization
app.get('/api/repair-requests/:id', 
  authenticateToken, 
  validateId, 
  checkValidation,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const userId = req.user.id;

      // Single query with user ownership check
      const result = await pool.query(
        `SELECT 
          id, user_id, original_img_url, img_filename, file_size, mime_type,
          ai_scan_desc, damage_type, damage_type_other_desc, clothing_type,
          clothing_type_other_desc, clothing_size, pickup_location, pickup_phone,
          thread_color_pref, estimated_cost, status, created_at, updated_at
         FROM repair_requests 
         WHERE id = $1 AND user_id = $2`,
        [id, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Repair request not found'
          }
        });
      }

      res.json({
        success: true,
        data: {
          repair_request: result.rows[0]
        }
      });

    } catch (error) {
      console.error('Get repair request error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to fetch repair request'
        }
      });
    }
  }
);

// POST /api/repair-requests - Create with comprehensive validation
app.post('/api/repair-requests', 
  authenticateToken, 
  validateRepairRequestCreate, 
  checkValidation,
  async (req, res) => {
    try {
      const {
        original_img_url, img_filename, file_size, mime_type, ai_scan_desc,
        damage_type, damage_type_other_desc, clothing_type, clothing_type_other_desc,
        clothing_size, pickup_location, pickup_phone, thread_color_pref, estimated_cost,status
      } = req.body;

      const userId = req.user.id;

      // Verify pickup_phone belongs to the user (security check)
      const phoneCheck = await pool.query(
        'SELECT id FROM users WHERE id = $1 AND phone = $2',
        [userId, pickup_phone]
      );

      if (phoneCheck.rows.length === 0) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Pickup phone must match your registered phone number'
          }
        });
      }

      // Create repair request with transaction
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        
        const result = await client.query(
          `INSERT INTO repair_requests (
            user_id, original_img_url, img_filename, file_size, mime_type, ai_scan_desc,
            damage_type, damage_type_other_desc, clothing_type, clothing_type_other_desc,
            clothing_size, pickup_location, pickup_phone, thread_color_pref, estimated_cost,
            status, created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
          RETURNING *`,
          [
            userId, original_img_url, img_filename, file_size, mime_type, ai_scan_desc,
            damage_type, damage_type_other_desc, clothing_type, clothing_type_other_desc,
            clothing_size, pickup_location, pickup_phone, thread_color_pref, estimated_cost,status
          ]
        );

        await client.query('COMMIT');
        
        res.status(201).json({
          success: true,
          data: {
            repair_request: result.rows[0]
          },
          message: 'Repair request created successfully'
        });
        
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Create repair request error:', error);
      
      // Handle specific database errors
      if (error.code === '23505') { // Unique violation
        return res.status(400).json({
          success: false,
          error: {
            code: 'DUPLICATE_ERROR',
            message: 'Duplicate entry detected'
          }
        });
      }
      
      if (error.code === '23503') { // Foreign key violation
        return res.status(400).json({
          success: false,
          error: {
            code: 'REFERENCE_ERROR',
            message: 'Invalid reference data'
          }
        });
      }
      
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to create repair request'
        }
      });
    }
  }
);

// PUT /api/repair-requests/:id - Update with proper validation
app.put('/api/repair-requests/:id', 
  authenticateToken, 
  validateId, 
  validateRepairRequestUpdate, 
  checkValidation,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const userId = req.user.id;

      // Only allow updates to specific fields based on user role
      const allowedFields = [
        'ai_scan_desc', 'damage_type','damage_type_other_desc', 'clothing_type','clothing_type_other_desc',
        'pickup_location', 'thread_color_pref','status'
      ];
      
      // Admin can update status and estimated_cost (implement role check)
      // if (req.user.role === 'admin') {
      //   allowedFields.push('status', 'estimated_cost');
      // }

      const updates = [];
      const values = [];
      let paramCount = 1;

      // Build dynamic update query with allowed fields only
      Object.keys(req.body).forEach(field => {
        if (allowedFields.includes(field) && req.body[field] !== undefined) {
          updates.push(`${field} = $${paramCount++}`);
          values.push(req.body[field]);
        }
      });

      if (updates.length === 0) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'No valid fields to update'
          }
        });
      }

      updates.push(`updated_at = NOW()`);
      values.push(id, userId);

      const query = `
        UPDATE repair_requests 
        SET ${updates.join(', ')}
        WHERE id = $${paramCount} AND user_id = $${paramCount + 1}
        RETURNING *
      `;

      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Repair request not found or access denied'
          }
        });
      }

      res.json({
        success: true,
        data: {
          repair_request: result.rows[0]
        },
        message: 'Repair request updated successfully'
      });

    } catch (error) {
      console.error('Update repair request error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to update repair request'
        }
      });
    }
  }
);

// DELETE /api/repair-requests/:id - Soft delete with proper authorization
app.delete('/api/repair-requests/:id', 
  authenticateToken, 
  validateId, 
  checkValidation,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const userId = req.user.id;

      // Check if request can be cancelled (only pending requests)
      const result = await pool.query(
        'SELECT status FROM repair_requests WHERE id = $1 AND user_id = $2',
        [id, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Repair request not found'
          }
        });
      }

      const currentStatus = result.rows[0].status;
      if (currentStatus !== 'Pending') {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_STATUS',
            message: 'Can only cancel pending requests'
          }
        });
      }

      // Soft delete by updating status to 'Cancelled'
      await pool.query(
        'UPDATE repair_requests SET status = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
        ['Selesai', id, userId]
      );

      res.json({
        success: true,
        message: 'Repair request cancelled successfully'
      });

    } catch (error) {
      console.error('Delete repair request error:', error);
      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to cancel repair request'
        }
      });
    }
  }
);
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Refresh token is required'
        }
      });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid token type'
        }
      });
    }

    const user = await pool.query('SELECT id, email FROM users WHERE id = $1', [decoded.id]);
    
    if (user.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'User not found'
        }
      });
    }

    const tokens = generateTokens(user.rows[0]);
    
    res.json({
      success: true,
      data: tokens
    });

  } catch (error) {
    res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Invalid refresh token'
      }
    });
  }
});
// ============= ERROR HANDLING =============

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.originalUrl} not found`
    }
  });
});


//backendaiapi
// Example in Node.js backend
const fetch = require("node-fetch");
async function getPredictions(imageBuffer) {
    const formData = new FormData();
    formData.append("file", imageBuffer, "image.jpg");

    const res = await fetch("http://yolo-api:8009/predict", {
        method: "POST",
        body: formData
    });
    return await res.json();
}


// Global error handler
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`REST API server running on port: ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
