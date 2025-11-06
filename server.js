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
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files AFTER session middleware, but BEFORE auth routes
app.use(express.static(path.join(__dirname, 'public'), {
  index: false
}));

// --- AUTHENTICATION AND AUTHORIZATION ---
const requireAuth = (req, res, next) => {
  console.log('Auth check - Session:', req.session);
  console.log('Auth check - User:', req.session?.user);
  
  if (req.session && req.session.user) {
    next();
  } else {
    console.log('Auth failed - no session or user');
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
                home: { title: "", subtitle: "", description: "", cta: "" },
                present: { title: "", subtitle: "", description: "", cta: "" },
                passerelles: { title: "", subtitle: "", description: "", cta: "" },
                facettes: { title: "", subtitle: "", description: "", cta: "" },
                about: { title: "", subtitle: "", description: "", cta: "" },
                contact: { title: "", subtitle: "", description: "", cta: "" }
            },
            fr: {
                home: { title: "", subtitle: "", description: "", cta: "" },
                present: { title: "", subtitle: "", description: "", cta: "" },
                passerelles: { title: "", subtitle: "", description: "", cta: "" },
                facettes: { title: "", subtitle: "", description: "", cta: "" },
                about: { title: "", subtitle: "", description: "", cta: "" },
                contact: { title: "", subtitle: "", description: "", cta: "" }
            }
        };
        fs.writeJsonSync(contentFilePath, defaultContent, { spaces: 2 });
    }
};

initUsersFile();
initContentFile();

// Login routes
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
    console.log('Setting language to:', lang);
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
    console.log('Reading content from:', contentFilePath);
    
    const content = fs.readJsonSync(contentFilePath);
    console.log('Content file read successfully');
    
    // If section and lang are specified, return specific section content (for admin)
    if (section && lang) {
      console.log(`Admin requesting: section=${section}, lang=${lang}`);
      if (!content[lang]) {
        content[lang] = {};
      }
      if (!content[lang][section]) {
        content[lang][section] = { title: "", subtitle: "", description: "" };
      }
      console.log('Returning section content:', content[lang][section]);
      return res.json(content[lang][section]);
    }
    
    // Otherwise, return all content for the current language (for frontend)
    const currentLang = req.cookies.lang || 'en';
    console.log('Frontend requesting, language:', currentLang);
    res.json(content[currentLang] || content.en);
  } catch (error) {
    console.error('Error reading content:', error);
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// Save content (Admin only) - ENHANCED WITH BETTER DEBUGGING
app.post('/api/content', requireAuth, upload.single('image'), (req, res) => {
  try {
    const { section, lang } = req.body;
    const contentFilePath = path.join(config.dataPath, config.contentFile);
    
    console.log('========== SAVE CONTENT REQUEST ==========');
    console.log('Authenticated user:', req.session.user);
    console.log('Section:', section);
    console.log('Language:', lang);
    console.log('Body fields:', Object.keys(req.body));
    console.log('Full body:', req.body);
    console.log('Content file path:', contentFilePath);
    
    // Check if file exists
    if (!fs.existsSync(contentFilePath)) {
      console.error('ERROR: Content file does not exist!');
      return res.status(500).json({ success: false, error: 'Content file not found' });
    }
    
    // Read current content
    console.log('Reading content file...');
    const content = fs.readJsonSync(contentFilePath);
    console.log('Content file read successfully');
    console.log('Current content structure:', Object.keys(content));

    // Ensure language and section structure exists
    if (!content[lang]) {
      console.log(`Creating language structure for: ${lang}`);
      content[lang] = {};
    }
    if (!content[lang][section]) {
      console.log(`Creating section structure for: ${lang}.${section}`);
      content[lang][section] = {};
    }

    console.log('Before update:', JSON.stringify(content[lang][section], null, 2));

    // Update all fields from the request body (except system fields)
    let updatedFields = [];
    for (const key in req.body) {
      if (!['section', 'lang'].includes(key)) {
        content[lang][section][key] = req.body[key];
        updatedFields.push(key);
        console.log(`✓ Updated ${key}:`, req.body[key].substring(0, 100) + (req.body[key].length > 100 ? '...' : ''));
      }
    }

    // Handle image upload if present
    if (req.file) {
      content[lang][section].imageUrl = `/uploads/${req.file.filename}`;
      updatedFields.push('imageUrl');
      console.log('✓ Image uploaded:', req.file.filename);
    }

    console.log('After update:', JSON.stringify(content[lang][section], null, 2));
    console.log('Updated fields:', updatedFields);

    // Write updated content back to file
    console.log('Writing to file...');
    try {
      fs.writeJsonSync(contentFilePath, content, { spaces: 2 });
      console.log('✓ Content written to file successfully!');
      
      // Verify the write
      const verifyContent = fs.readJsonSync(contentFilePath);
      console.log('Verification - file content after write:', JSON.stringify(verifyContent[lang][section], null, 2));
      
      console.log('========== SAVE SUCCESSFUL ==========');
      res.json({ success: true, content: content[lang][section], updatedFields });
    } catch (writeError) {
      console.error('ERROR writing to file:', writeError);
      return res.status(500).json({ success: false, error: 'Failed to write to file: ' + writeError.message });
    }
  } catch (error) {
    console.error('========== SAVE FAILED ==========');
    console.error('Error saving content:', error);
    console.error('Stack trace:', error.stack);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- USER MANAGEMENT API ROUTES ---

// Get all users (Admin only)
app.get('/api/users', requireAuth, (req, res) => {
  try {
    const usersFilePath = path.join(config.dataPath, config.usersFile);
    const users = fs.readJsonSync(usersFilePath);
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
    
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    
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
    
    if (req.session.user.id === id) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }
    
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
  console.log(`Data directory: ${config.dataPath}`);
  console.log(`Content file: ${path.join(config.dataPath, config.contentFile)}`);
});