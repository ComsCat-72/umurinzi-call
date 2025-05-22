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
app.listen(config.port, () => {
      console.log(`Server running on http://localhost:${config.port}`);
    });


// Start the server
startServer();


const fetchData = async () => {
  try {
    const response = await fetch("https://umurinzi-8o2d.onrender.com");
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
