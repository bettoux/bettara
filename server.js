import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import multer from 'multer';
import fs from 'fs-extra';
import path from 'path';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
const { v4: uuidv4 } = await import('uuid'); 

import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dataPath = path.join(__dirname, 'data');

const app = express();
const PORT = process.env.PORT || 3000;
const upload = multer({ dest: 'public/uploads/' });

// Configuration
const config = {
  dataPath: path.join(__dirname, 'data'),
  contentFile: 'content.json',
  usersFile: 'users.json'
};

// Ensure data directory exists
fs.ensureDirSync(config.dataPath);
fs.ensureDirSync(path.join(__dirname, 'public', 'uploads'));

// Middleware setup (ORDER MATTERS!)
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'supersecuresecretkey',
  resave: false,
  saveUninitialized: false, // Changed from true to false
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files AFTER session middleware, but BEFORE auth routes
// This allows static files to be served, but protected routes will be checked first
app.use(express.static(path.join(__dirname, 'public'), {
  index: false // Don't automatically serve index files
}));

// --- AUTHENTICATION AND AUTHORIZATION ---
const requireAuth = (req, res, next) => {
  console.log('Auth check - Session:', req.session);
  console.log('Auth check - User:', req.session?.user);
  
  if (req.session && req.session.user) {
    next();
  } else {
    console.log('Auth failed - no session or user');
    // For API calls, return JSON error instead of redirect
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }
    res.redirect('/login');
  }
};

// Ensure initial users file exists
const initUsersFile = () => {
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    if (!fs.existsSync(usersFilePath)) {
        console.log("Users file not found. Creating default admin user.");
        const hashedPassword = bcrypt.hashSync('bettara123', 10);
        const defaultUsers = [{ username: 'bettara', password: hashedPassword, id: uuidv4() }];
        fs.writeJsonSync(usersFilePath, defaultUsers, { spaces: 2 });
    }
};

// Ensure initial content file exists with proper structure
const initContentFile = () => {
    const contentFilePath = path.join(config.dataPath, config.contentFile);
    if (!fs.existsSync(contentFilePath)) {
        console.log("Content file not found. Creating default content structure.");
        const defaultContent = {
            en: {
                home: { title: "", subtitle: "", description: "" },
                present: { title: "", subtitle: "", description: "" },
                passerelles: { title: "", subtitle: "", description: "" },
                facettes: { title: "", subtitle: "", description: "" },
                about: { title: "", subtitle: "", description: "" },
                contact: { title: "", subtitle: "", description: "" }
            },
            fr: {
                home: { title: "", subtitle: "", description: "" },
                present: { title: "", subtitle: "", description: "" },
                passerelles: { title: "", subtitle: "", description: "" },
                facettes: { title: "", subtitle: "", description: "" },
                about: { title: "", subtitle: "", description: "" },
                contact: { title: "", subtitle: "", description: "" }
            }
        };
        fs.writeJsonSync(contentFilePath, defaultContent, { spaces: 2 });
    }
};

initUsersFile();
initContentFile();

// Login routes (must come BEFORE admin route)
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt for:', username);
  
  try {
    const users = fs.readJsonSync(path.join(config.dataPath, config.usersFile));
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { username: user.username, id: user.id };
      console.log('Login successful, session:', req.session);
      
      // Save session before redirecting
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/login?error=1');
        }
        console.log('Session saved successfully');
        return res.redirect('/admin.html');
      });
    } else {
      console.log('Login failed - invalid credentials');
      res.redirect('/login?error=1');
    }
  } catch (error) {
    console.error('Login error:', error);
    res.redirect('/login?error=1');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Protect admin.html specifically
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Admin route - also protected
app.get('/admin', requireAuth, (req, res) => {
  res.redirect('/admin.html');
});

// --- ROOT ROUTE & LANGUAGE HANDLER ---
app.get('/', (req, res) => {
    if (!req.cookies.lang) {
        res.cookie('lang', 'en', { maxAge: 3600000 * 24 * 30, httpOnly: true });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/set-lang', (req, res) => {
    const { lang } = req.body;
    if (['en', 'fr'].includes(lang)) {
        res.cookie('lang', lang, { maxAge: 3600000 * 24 * 30, httpOnly: true });
        return res.json({ success: true, lang });
    }
    res.status(400).json({ success: false, message: 'Invalid language' });
});

// --- API routes ---

// Get content - handles both admin (with section/lang params) and frontend (with cookie)
app.get('/api/content', (req, res) => {
  const { section, lang } = req.query;
  
  try {
    const contentFilePath = path.join(config.dataPath, config.contentFile);
    const content = fs.readJsonSync(contentFilePath);
    
    // If section and lang are specified, return specific section content (for admin)
    if (section && lang) {
      if (!content[lang]) {
        content[lang] = {};
      }
      if (!content[lang][section]) {
        content[lang][section] = { title: "", subtitle: "", description: "" };
      }
      return res.json(content[lang][section]);
    }
    
    // Otherwise, return all content for the current language (for frontend)
    const currentLang = req.cookies.lang || 'en';
    res.json(content[currentLang] || content.en);
  } catch (error) {
    console.error('Error reading content:', error);
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// Save content (Admin only)
app.post('/api/content', requireAuth, upload.single('image'), (req, res) => {
  try {
    const { section, lang } = req.body;
    const contentFilePath = path.join(config.dataPath, config.contentFile);
    
    console.log('=== SAVE REQUEST ===');
    console.log('Section:', section);
    console.log('Language:', lang);
    console.log('Body:', req.body);
    
    const content = fs.readJsonSync(contentFilePath);

    // Ensure language and section structure exists
    if (!content[lang]) {
      content[lang] = {};
    }
    if (!content[lang][section]) {
      content[lang][section] = {};
    }

    // Update all fields from the request body (except system fields)
    for (const key in req.body) {
      if (!['section', 'lang'].includes(key)) {
        content[lang][section][key] = req.body[key];
        console.log(`Set ${key}:`, req.body[key]);
      }
    }

    // Handle image upload if present
    if (req.file) {
      content[lang][section].imageUrl = `/uploads/${req.file.filename}`;
      console.log('Image uploaded:', req.file.filename);
    }

    // Write updated content back to file
    fs.writeJsonSync(contentFilePath, content, { spaces: 2 });
    console.log('Content written to file successfully');
    console.log('Updated section:', JSON.stringify(content[lang][section], null, 2));
    
    res.json({ success: true, content: content[lang][section] });
  } catch (error) {
    console.error('Error saving content:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- USER MANAGEMENT API ROUTES ---

// Get all users (Admin only)
app.get('/api/users', requireAuth, (req, res) => {
  try {
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    const users = fs.readJsonSync(usersFilePath);
    // Don't send passwords to frontend
    const safeUsers = users.map(u => ({ id: u.id, username: u.username }));
    res.json({ success: true, users: safeUsers });
  } catch (error) {
    console.error('Error reading users:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add new user (Admin only)
app.post('/api/users', requireAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    const users = fs.readJsonSync(usersFilePath);
    
    // Check if username already exists
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    
    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword
    };
    
    users.push(newUser);
    fs.writeJsonSync(usersFilePath, users, { spaces: 2 });
    
    console.log('New user created:', username);
    res.json({ success: true, user: { id: newUser.id, username: newUser.username } });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete user (Admin only)
app.delete('/api/users/:id', requireAuth, (req, res) => {
  try {
    const { id } = req.params;
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    const users = fs.readJsonSync(usersFilePath);
    
    // Don't allow deleting yourself
    if (req.session.user.id === id) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }
    
    // Don't allow deleting if it's the last user
    if (users.length === 1) {
      return res.status(400).json({ success: false, error: 'Cannot delete the last user' });
    }
    
    const updatedUsers = users.filter(u => u.id !== id);
    
    if (updatedUsers.length === users.length) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    fs.writeJsonSync(usersFilePath, updatedUsers, { spaces: 2 });
    
    console.log('User deleted:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Change password (Admin only)
app.put('/api/users/:id/password', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    const users = fs.readJsonSync(usersFilePath);
    
    const user = users.find(u => u.id === id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    user.password = await bcrypt.hash(password, 10);
    fs.writeJsonSync(usersFilePath, users, { spaces: 2 });
    
    console.log('Password changed for user:', user.username);
    res.json({ success: true });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log(`Admin login - username: bettara, password: bettara123`);
});