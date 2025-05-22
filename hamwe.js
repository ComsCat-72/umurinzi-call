const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const multer = require('multer');
const Datastore = require('nedb');
const uuid = require('uuid').v4;
const retry = require('async-retry');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const fs = require('fs');
const path = require('path');
const app = express();
const server = http.createServer(app);
let connected_users = [];
const is_sleeped = false;

// Enhanced Socket.IO configuration with error handling
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000,
    skipMiddlewares: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Configuration with environment variables
const config = {
  maxFileSize: 50 * 1024 * 1024,
  maxRetries: 5,
  retryMinTimeout: 1000,
  retryMaxTimeout: 5000,
  globalRoom: 'global',
  adminRole: 0,
  userRole: 1,
  sessionSecret: process.env.SESSION_SECRET || '____ioxss______',
  port: process.env.PORT || 3000,
  uploadDir: path.join(__dirname, 'uploads'), // Directory to store uploaded files
  dataDir: path.join(__dirname, 'data') // Directory to store database files
};

// Ensure directories exist
[config.uploadDir, config.dataDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Initialize NeDB databases
const db = {
  admins: new Datastore({ filename: path.join(config.dataDir, 'admins.db'), autoload: true }),
  users: new Datastore({ filename: path.join(config.dataDir, 'users.db'), autoload: true }),
  messages: new Datastore({ filename: path.join(config.dataDir, 'messages.db'), autoload: true }),
  sessions: new Datastore({ filename: path.join(config.dataDir, 'sessions.db'), autoload: true })
};

// Create indexes
db.admins.ensureIndex({ fieldName: 'name', unique: true });
db.admins.ensureIndex({ fieldName: 'secret', unique: true });
db.users.ensureIndex({ fieldName: 'name', unique: true });
db.users.ensureIndex({ fieldName: 'secret', unique: true });
db.messages.ensureIndex({ fieldName: 'id', unique: true });
db.messages.ensureIndex({ fieldName: 'createdAt' });

// Helper function to promisify NeDB operations
function promisifyDBOperation(operation, ...args) {
  return new Promise((resolve, reject) => {
    operation(...args, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// Admin data to be inserted at startup
const initialAdmins = [
  { name: 'dev', secret: '---', role: config.adminRole, active: false, lastSeen: null },
  { name: 'igirimezec', secret: 'comscat@123', role: config.adminRole, active: false, lastSeen: null },
  {
    name: '@m_design', secret: 'do__', role: config.adminRole, active: false, lastSeen: null,
    name: "steven", secret: "stevendev@@", role: config.adminRole, active: false, lastSeen: null
  },
  { name: "bonheur", secret: "bonheur@123", role: config.adminRole, active: false, lastSeen: null },
];

// Allowed file types configuration
const ALLOWED_FILE_TYPES = {
  image: {
    mimeTypes: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/svg+xml',
      'image/tiff',
      'image/bmp',
      'image/x-icon',
      'image/vnd.adobe.photoshop',
      'image/heif',
      'image/heic'
    ],
    maxSize: 50 * 1024 * 1024
  },
  pdf: {
    mimeTypes: ['application/pdf'],
    maxSize: 100 * 1024 * 1024
  },
  zip: {
    mimeTypes: [
      'application/zip',
      'application/x-zip-compressed',
      'application/gzip',
      'application/x-gzip',
      'application/vnd.rar',
      'application/x-7z-compressed',
      'application/x-tar',
      'application/x-bzip2',
      'application/x-lzh',
      'application/x-compress',
      'application/x-apple-diskimage'
    ],
    maxSize: 150 * 1024 * 1024
  },
  video: {
    mimeTypes: [
      'video/mp4',
      'video/webm',
      'video/ogg',
      'video/quicktime',
      'video/x-msvideo',
      'video/x-flv',
      'video/3gpp',
      'video/x-matroska',
      'video/mpeg',
      'video/x-ms-wmv',
      'video/x-sgi-movie',
      'video/x-m4v'
    ],
    maxSize: 200 * 1024 * 1024
  },
  audio: {
    mimeTypes: [
      'audio/mpeg',
      'audio/ogg',
      'audio/wav',
      'audio/aac',
      'audio/midi',
      'audio/x-ms-wma',
      'audio/x-ms-wax',
      'audio/x-flac',
      'audio/x-m4a',
      'audio/vnd.rn-mpeg-url'
    ],
    maxSize: 100 * 1024 * 1024
  },
  document: {
    mimeTypes: [
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'text/plain',
      'application/rtf',
      'application/vnd.oasis.opendocument.text',
      'application/vnd.oasis.opendocument.spreadsheet',
      'application/vnd.oasis.opendocument.presentation',
      'text/csv',
      'application/json',
      'text/html',
      'application/xml',
      'text/xml',
      'application/vnd.google-earth.kml+xml',
      'application/vnd.google-earth.kmz',
      'application/epub+zip',
      'application/vnd.ms-publisher',
      'application/x-abiword'
    ],
    maxSize: 50 * 1024 * 1024
  },
  spreadsheet: {
    mimeTypes: [
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/csv'
    ],
    maxSize: 50 * 1024 * 1024
  },
  presentation: {
    mimeTypes: [
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ],
    maxSize: 50 * 1024 * 1024
  },
  executable: {
    mimeTypes: [
      'application/x-msdownload',
      'application/x-ms-dos-executable',
      'application/x-msi',
      'application/x-sh',
      'application/x-python',
      'application/java-archive',
      'application/x-bat',
      'application/x-perl',
      'application/x-ruby'
    ],
    maxSize: 100 * 1024 * 1024
  },
  font: {
    mimeTypes: [
      'font/otf',
      'font/ttf',
      'font/woff',
      'font/woff2',
      'application/font-sfnt'
    ],
    maxSize: 10 * 1024 * 1024
  },
  code: {
    mimeTypes: [
      'text/javascript',
      'text/css',
      'application/json',
      'text/html',
      'application/xml',
      'application/x-php',
      'application/x-java-source',
      'text/x-c',
      'text/x-c++src',
      'text/x-python',
      'text/x-script.perl',
      'text/x-ruby',
      'application/typescript',
      'text/markdown'
    ],
    maxSize: 20 * 1024 * 1024
  },
  cad: {
    mimeTypes: [
      'application/acad',
      'application/x-autocad',
      'application/dxf',
      'image/vnd.dxf',
      'application/dwg',
      'image/vnd.dwg'
    ],
    maxSize: 500 * 1024 * 1024
  }
};



app.use(cors());
// Body parsing middleware with size limits
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '10000mb' }));

// Serve static files from upload directory
app.use('/uploads', express.static(config.uploadDir));

// Session middleware with file store
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true,
  store: new FileStore({
    path: path.join(config.dataDir, 'sessions'),
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Multer configuration to save files to disk
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, config.uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1e5 * 1024 * 1024, // 10 GB max file size
  },
  // No fileFilter means all file types are allowed
});

// Active users tracking with cleanup mechanism
const activeUsers = new Map(); // socketId -> {userId, userName, role}
const userSockets = new Map(); // userId -> [socketIds]

// Helper functions with enhanced error handling
function bytesToMB(bytes) {
  return (bytes / (1024 * 1024)).toFixed(2);
}

function getFileType(mimeType) {
  console.log(mimeType);
  for (const [type, config] of Object.entries(ALLOWED_FILE_TYPES)) {
    if (config.mimeTypes.includes(mimeType)) {
      return type;
    }
  }
  return null;
}

async function withRetry(operation, operationName = 'operation') {
  return retry(
    async (bail) => {
      try {
        return await operation();
      } catch (error) {
        console.error(`Error in ${operationName}:`, error);
        if (error.message.includes('ECONNREFUSED') ||
          error.message.includes('ETIMEDOUT')) {
          throw error;
        }
        bail(error);
      }
    },
    {
      retries: config.maxRetries,
      minTimeout: config.retryMinTimeout,
      maxTimeout: config.retryMaxTimeout,
      onRetry: (err) => {
        console.log(`Retrying ${operationName} due to error:`, err.message);
      }
    }
  );
}

// Initialize database with initial data
async function initializeDB() {
  try {
    await withRetry(async () => {
      // Insert initial admins if they don't exist
      for (const admin of initialAdmins) {
        try {
          const existingAdmin = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { name: admin.name });

          if (!existingAdmin) {
            await promisifyDBOperation(db.admins.insert.bind(db.admins), admin);
          }
        } catch (err) {
          console.error('Error initializing admin:', admin.name, err);
        }
      }
    }, 'database initialization');

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization failed:', err);
    process.exit(1);
  }
}

// API Endpoints with enhanced error handling

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage()
  });
});

// User registration (admin only)
app.post('/api/register', async (req, res) => {
  try {
    const { name, secret, adminSecret, role } = req.body;

    console.log(req.body)

    if (!name || !secret || !adminSecret || role === undefined) {
      return res.status(400).json({ status: false, message: 'Name, secret, and adminSecret are required' });
    }

    // Verify admin
    const admin = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: adminSecret });

    if (!admin) {
      return res.status(403).json({ status: false, message: 'Only admins can register users' });
    }

    // Check if user already exists
    const existingUser = await promisifyDBOperation(db.users.findOne.bind(db.users), { name });
    if (existingUser) {
      return res.status(400).json({ status: false, message: 'User already exists' });
    }

    // Insert new user
    const newUser = {
      name,
      secret,
      role,
      active: false,
      lastSeen: null,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    if (role === 1) {
      await promisifyDBOperation(db.users.insert.bind(db.users), newUser);
    }

    else if (role === 0) {
      await promisifyDBOperation(db.admins.insert.bind(db.admins), newUser);
    }

    res.json({ status: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ status: false, message: 'Registration failed' });
  }
});

// User login (session-based)
app.post('/api/login', async (req, res) => {
  try {
    const { secret } = req.body;



    if (!secret) {
      return res.status(400).json({ status: false, message: 'Secret is required' });
    }

    // Attempt to find user in either collection
    let user = await promisifyDBOperation(db.users.findOne.bind(db.users), { secret: secret });
    let isRegularUser = true;

    if (!user) {
      user = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
      isRegularUser = false;
    }

    if (!user) {
      return res.status(401).json({ status: false, message: 'Invalid secret' });
    }

    // Update lastSeen only for regular users
    if (isRegularUser) {
      await withRetry(() =>
        promisifyDBOperation(
          db.users.update.bind(db.users),
          { _id: user._id },
          { $set: { lastSeen: new Date() } }
        ),
        'update user lastSeen'
      );
    }

    // Remove sensitive fields before sending response
    const { secret: _omit, ...userData } = user;

    return res.json({
      status: true,
      message: 'Login successful',
      user: userData
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      status: false,
      message: 'An error occurred during login'
    });
  }
});

// Get all users (including admins) with status
app.get('/api/users', async (req, res) => {
  try {
    const [users, admins] = await Promise.all([
      withRetry(() => promisifyDBOperation(db.users.find.bind(db.users), {}), 'fetch users'),
      withRetry(() => promisifyDBOperation(db.admins.find.bind(db.admins), {}), 'fetch admins')
    ]);

    // Combine and format user data
    const allUsers = [...users, ...admins].map(user => ({
      id: user._id,
      name: user.name,
      role: user.role,
      active: user.active || false,
      lastSeen: user.lastSeen
    }));

    res.json({ status: true, data: allUsers });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ status: false, message: 'Failed to fetch users' });
  }
});

app.delete('/api/wipe', async (req, res) => {
  try {

    const { secret } = req.body;

    if (!secret) {
      return res.status(400).json({ status: false, message: 'Admin secret is required' });
    }

    // Verify admin
    const admin = await withRetry(() => promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret }), 'admin verification');

    if (!admin || admin.role !== config.adminRole) {
      return res.status(403).json({ status: false, message: 'Only admins can delete users' });
    }

    // Check if user exists
    let _user = await promisifyDBOperation(db.users.find.bind(db.users), { role: config.userRole });
    let user = _user.length > 0 ? _user[0] : null;
    if (!user) {
      return res.status(404).json({ status: false, message: 'No users found to delede!' });
    }

    // Delete user and their messages

    for (const user of _user) {

      const id = user._id;

      await withRetry(async () => {
        await promisifyDBOperation(db.users.remove.bind(db.users), { _id: id });
        await promisifyDBOperation(db.messages.remove.bind(db.messages), { user: user.name }, { multi: true });
      }, 'delete user transaction');

      // Notify about user deletion
      const globalRoom = config.globalRoom;
      io.to(globalRoom).emit('notification', {
        type: 'user_deleted',
        message: `User ${user.name} has been removed from a chat permanently!`,
        timestamp: new Date()
      });


    }

    res.json({ status: true, message: 'All users are deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ status: false, message: 'Failed to delete user' });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { secret } = req.body;

    if (!secret || !id) {
      return res.status(400).json({ status: false, message: 'Admin secret and user ID are required' });
    }

    // Verify admin
    const admin = await withRetry(() => promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret }), 'admin verification');

    if (!admin || admin.role !== config.adminRole) {
      return res.status(403).json({ status: false, message: 'Only admins can delete users' });
    }

    // Check if user exists
    let _user = await promisifyDBOperation(db.users.find.bind(db.users), { _id: id });
    let user = _user[0];
    if (!user) {
      return res.status(404).json({ status: false, message: 'User not found' });
    }

    if (user.role === config.adminRole) {
      return res.status(401).json({ status: false, message: 'Process denied!' });
    }

    // Delete user and their messages
    await withRetry(async () => {
      await promisifyDBOperation(db.users.remove.bind(db.users), { _id: id });
      await promisifyDBOperation(db.messages.remove.bind(db.messages), { user: user.name }, { multi: true });
    }, 'delete user transaction');

    // Notify about user deletion
    const globalRoom = config.globalRoom;
    io.to(globalRoom).emit('notification', {
      type: 'user_deleted',
      message: `User ${user.name} has been removed from a chat permanently!`,
      timestamp: new Date()
    });

    res.json({ status: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ status: false, message: 'Failed to delete user' });
  }
});


// Message endpoints

// Send a message (text or file)
app.post('/api/message/:secret', upload.single('file'), async (req, res) => {
  try {


    const secret = req.params?.secret;

    if (!secret) return res.status(401).json({ status: false, message: "System's Adminstration Removed your account!" });

    let usered = await promisifyDBOperation(db.users.findOne.bind(db.users), { secret: secret });

    if (!usered) {
      usered = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
    }

    if (!usered) {
      return res.status(401).json({ status: false, message: "System's Adminstration Removed your account!" });
    }


    const { user, role, message, is_encrypted = false, has_reply = false, reply = null } = req.body;
    const file = req.file;

    const messageId = uuid();
    const isEncrypted = is_encrypted === 'true';

    // Prepare message document
    const messageDoc = {
      id: messageId,
      user,
      role: parseInt(role),
      message: message || '',
      type: file ? 'file' : 'text',
      is_encrypted: isEncrypted,
      createdAt: new Date(),
      updatedAt: new Date(),
      has_reply: has_reply,
    };

    if (has_reply === true) {

      messageDoc.reply = {
        user: reply.user,
        message: reply.message,
      }

    }

    if (file) {
      const fileType = getFileType(file.mimetype);

      // Add file metadata to message document (without the buffer)
      messageDoc.file = {
        name: file.originalname,
        type: fileType || 'dat',
        mimeType: file.mimetype,
        size: file.size,
        path: file.path.replace(config.uploadDir, ''), // Store relative path
        url: `/uploads${file.path.replace(config.uploadDir, '')}` // Public URL
      };
    }

    // Save message to database
    await withRetry(() => promisifyDBOperation(db.messages.insert.bind(db.messages), messageDoc), 'message save');

    // Broadcast message to all clients in global room
    io.to(config.globalRoom).emit('message', messageDoc);

    res.json({ status: true, message: 'Message sent successfully', data: messageDoc });
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ status: false, message: 'Failed to send message' });
  }
});

// Get all messages
app.get('/api/messages/:secret', async (req, res) => {
  try {

    const secret = req.params?.secret;

    if (!secret) return res.status(401).json({ status: false, message: "System's Adminstration Removed your account!" });

    let user = await promisifyDBOperation(db.users.findOne.bind(db.users), { secret: secret });
    let isRegularUser = true;

    if (!user) {
      user = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
      isRegularUser = false;
    }

    if (!user) {
      return res.status(401).json({ status: false, message: "System's Adminstration Removed your account!" });
    }


    const messages = await withRetry(() =>
      promisifyDBOperation(db.messages.find.bind(db.messages), {})
      , 'fetch messages'
    );

    // For file messages, ensure the URL is properly constructed
    const processedMessages = messages.map(msg => {
      if (msg.file && msg.path) {
        return {
          ...msg,
          file: {
            ...msg.file,
            url: `/uploads${msg.path}` // Ensure URL is properly constructed
          }
        };
      }
      return msg;
    });

    res.json({ status: true, data: processedMessages });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ status: false, message: 'Failed to fetch messages' });
  }
});


app.delete('/api/messages/:id/:secret', async (req, res) => {


  const secret = req.params?.secret;

  if (!secret) return res.status(401).json({ status: false, message: "System's Adminstration Removed your account!" });

  let usered = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });

  if (!usered) {
    return res.status(401).json({ status: false, message: "Message can't be deleted only Admin can do this." });
  }

  try {
    const { id } = req.params;// Adjust if you're using req.query or headers instead

    if (!id) {
      return res.status(400).json({ status: false, message: 'Message ID and secret are required' });
    }

    // Find the message
    const message = await withRetry(() => promisifyDBOperation(db.messages.findOne.bind(db.messages), { id }), 'find message');

    if (!message) {
      return res.status(404).json({ status: false, message: 'Message not found' });
    }

    // Delete associated file if present
    if (message.file && message.file.path) {
      const filePath = path.join(config.uploadDir, message.file.path);

      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log(`Deleted file: ${filePath}`);
        }
      } catch (err) {
        console.error('File deletion error:', err);
      }
    }

    // Delete the message from DB
    await withRetry(() => promisifyDBOperation(db.messages.remove.bind(db.messages), { id }), 'delete message');

    // Emit notification to clients
    io.emit('notification', {
      type: 'message_deleted',
      messageId: id,
      timestamp: new Date()
    });

    res.json({ status: true, message: 'Message and file deleted successfully' });
  } catch (err) {
    console.error('Error deleting message:', err);
    res.status(500).json({ status: false, message: 'Failed to delete message' });
  }
});


app.get('/api/files/:messageId/download', async (req, res) => {
  try {
    const { messageId } = req.params;

    // 1. Find the message with the file info
    const message = await promisifyDBOperation(db.messages.findOne.bind(db.messages), { id: messageId });

    if (!message || !message.file) {
      return res.status(404).json({ status: false, message: 'File not found in message' });
    }

    const filePath = path.join(config.uploadDir, message.file.path);

    console.log(filePath);

    // 2. Check if file actually exists on disk
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ status: false, message: 'File not found on server' });
    }

    // 3. Set download headers
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${message.file.name}"`,
      'Content-Length': message.file.size
    });

    // 4. Pipe the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ status: false, message: 'Error downloading file' });
  }
});

app.use((_, res) => res.status(404).json({ status: false, message: 404 }));



// Enhanced Socket.IO connection handling with status tracking
io.on('connection', async (socket) => {

  console.log('A user connected:', socket.id);

  socket.on('sleep-this', async (secret, callback) => {

    if (!secret) {
      return callback({ status: false, message: 'Secret is required' });
    } else {

      const is_exists = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
      if (!is_exists) {
        return callback({ status: false, message: 'Invalid secret' });
      }
      if (is_sleeped) {
        return callback({ status: false, message: 'System is already sleeped' });
      }
      is_sleeped = true;
      io.to(config.globalRoom).emit('sleeped', { status: true, message: 'System is sleeped' });
      return callback({ status: true, message: 'System is sleeped' });


    }
  });


  socket.on('wake-up', async (secret, callback) => {

    if (!secret) {
      return callback({ status: false, message: 'Secret is required' });
    } else {

      const is_exists = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
      if (!is_exists) {
        return callback({ status: false, message: 'Invalid secret' });
      }
      if (!is_sleeped) {
        return callback({ status: false, message: 'System is not sleeped' });
      }
      is_sleeped = false;
      io.to(config.globalRoom).emit('wake-up', { status: true, message: 'System is activated!' });
      return callback({ status: true, message: 'System is activated!' });


    }
  });



  // Handle initial connection with authentication
  socket.on('connected-first', async ({ secret }, callback) => {
    try {
      if (!secret) {
        return callback({ status: false, message: 'Secret is required' });
      }

      if (!secret) {
        return res.status(400).json({ status: false, message: 'Secret is required' });
      }

      // Attempt to find user in either collection
      let user = await promisifyDBOperation(db.users.findOne.bind(db.users), { secret: secret });
      let isRegularUser = true;

      if (!user) {
        user = await promisifyDBOperation(db.admins.findOne.bind(db.admins), { secret: secret });
        isRegularUser = false;
      }

      if (!user) {
        return callback({ status: false, message: 'Invalid!' });
      }

      // Check if user is already connected from another device
      if (userSockets.has(user._id)) {
        const existingSockets = userSockets.get(user._id);
        existingSockets.forEach(sockId => {
          try {
            return callback({ status: 401, message: 'Logged in from another location' });
          } catch (err) {
            console.error('Error disconnecting existing socket:', err);
          }
        });
      }

      // Mark user as active
      await withRetry(async () => {
        const updateOperation = user.role === config.adminRole ?
          promisifyDBOperation(db.admins.update.bind(db.admins), { _id: user._id }, { $set: { active: true, lastSeen: new Date() } }) :
          promisifyDBOperation(db.users.update.bind(db.users), { _id: user._id }, { $set: { active: true, lastSeen: new Date() } });
        await updateOperation;
      }, 'update user status');

      // Track active user
      activeUsers.set(socket.id, {
        userId: user._id,
        userName: user.name,
        role: user.role
      });

      // Track user's sockets
      if (!userSockets.has(user._id)) {
        userSockets.set(user._id, []);
      }
      userSockets.get(user._id).push(socket.id);

      // Join global room
      socket.join(config.globalRoom);

      // Get initial data for the user
      const [messages, allUsers] = await Promise.all([
        withRetry(() =>
          promisifyDBOperation(db.messages.find.bind(db.messages), {})
          , 'fetch messages'),
        withRetry(() =>
          Promise.all([
            promisifyDBOperation(db.users.find.bind(db.users), {}),
            promisifyDBOperation(db.admins.find.bind(db.admins), {})
          ]).then(([users, admins]) => [...users, ...admins]), 'fetch all users')
      ]);

      // For file messages, ensure the URL is properly constructed
      const processedMessages = messages.map(msg => {
        if (msg.file && msg.path) {
          return {
            ...msg,
            file: {
              ...msg.file,
              url: `/uploads${msg.path}` // Ensure URL is properly constructed
            }
          };
        }
        return msg;
      });

      // Format user status data
      const userStatusData = allUsers.map(u => ({
        id: u._id,
        name: u.name,
        role: u.role,
        active: u.active || false,
        lastSeen: u.lastSeen
      }));
      connected_users.push(secret);
      // Send initial data to user
      callback({
        status: true,
        user: {
          id: user._id,
          name: user.name,
          role: user.role
        },
        messages: processedMessages,
        users: userStatusData
      });

      // Notify others about new connection
      io.to(config.globalRoom).emit('user-status', {
        userId: user._id,
        name: user.name,
        status: 'online',
        timestamp: new Date()
      });

      console.log(`User ${user.name} connected successfully`);
    } catch (err) {

      console.error('Error during initial connection:', err);
      callback({ status: false, message: 'Connection failed' });
      socket.disconnect(true);
    }
  });

  // Handle disconnection with cleanup
  socket.on('disconnect', async () => {
    try {
      const userInfo = activeUsers.get(socket.id);
      if (!userInfo) return;

      const { userId, userName, role } = userInfo;

      // Remove socket from tracking
      activeUsers.delete(socket.id);
      connected_users = connected_users.filter(user => user !== userId);

      // Remove socket from user's sockets
      if (userSockets.has(userId)) {
        const sockets = userSockets.get(userId).filter(id => id !== socket.id);
        if (sockets.length === 0) {
          // Last socket disconnected - mark user as offline
          await withRetry(async () => {
            const updateOperation = role === config.adminRole ?
              promisifyDBOperation(db.admins.update.bind(db.admins), { _id: userId }, { $set: { active: false, lastSeen: new Date() } }) :
              promisifyDBOperation(db.users.update.bind(db.users), { _id: userId }, { $set: { active: false, lastSeen: new Date() } });
            await updateOperation;
          }, 'update user status');

          // Notify about user disconnection
          io.to(config.globalRoom).emit('user-status', {
            userId,
            name: userName,
            status: 'offline',
            timestamp: new Date()
          });

          // Clean up
          userSockets.delete(userId);
        } else {
          userSockets.set(userId, sockets);
        }
      }

      console.log(`User ${userName} disconnected`);
    } catch (err) {
      console.error('Error handling disconnect:', err);
    }
  });

  // Handle errors
  socket.on('error', (err) => {
    console.error('Socket error:', err);
  });

  // Heartbeat to keep connection alive
  socket.on('ping', (cb) => {
    if (typeof cb === 'function') {
      cb();
    }
  });
});

// Start server with enhanced error handling
async function startServer() {
  try {
    await initializeDB();

    server.listen(config.port, () => {
      console.log(`Server running on http://localhost:${config.port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
      console.error('Server error:', err);
      clearInterval(cleanupInterval);
      process.exit(1);
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (err) => {
      console.error('Unhandled rejection:', err);
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
      console.error('Uncaught exception:', err);
      clearInterval(cleanupInterval);
      process.exit(1);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

// Start the server
startServer();


const fetchData = async () => {
  try {
    const response = await fetch("https://hamwe-five-first.onrender.com/api/get-message");
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.text();
    console.log("Response:");
  } catch (error) {
    console.error("Error fetching data:", error.message);
  }

  setTimeout(fetchData, 5000);
};
setTimeout(fetchData,5000);

module.exports = app;