import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import multer from 'multer';
import fs from 'fs-extra';
import path from 'path';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { MongoClient } from 'mongodb';
const { v4: uuidv4 } = await import('uuid'); 

import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const upload = multer({ dest: 'public/uploads/' });

// MongoDB Configuration
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://your-connection-string-here';
const DB_NAME = 'bettara';

let db;
let contentCollection;
let usersCollection;

// Connect to MongoDB
async function connectToDatabase() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('✓ Connected to MongoDB');
    
    db = client.db(DB_NAME);
    contentCollection = db.collection('content');
    usersCollection = db.collection('users');
    
    // Initialize default data if needed
    await initializeDatabase();
    
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

// Initialize database with default data
async function initializeDatabase() {
  // Check if content exists
  const contentCount = await contentCollection.countDocuments();
  if (contentCount === 0) {
    console.log('Initializing content collection...');
    const defaultContent = {
      _id: 'content',
      en: {
        home: { title: "BETTARA", subtitle: "Connecting people", description: "To self. To the other. To audiences.", cta: "Start Exploration" },
        present: { title: "Present, pas presse", description: "The art of mindful, unhurried presence.", cta: "Deep Dive →", placeholder: "Visual Asset Placeholder" },
        passerelles: { venture_name: "Venture 2", title: "Passerelles", description: "Passerelles is dedicated to forging strategic connections.", cta: "View Projects →", placeholder: "Strategic Bridge Visual" },
        facettes: { title: "Facettes", description: "A celebration of the multi-faceted professional.", cta: "Discover Facettes →", placeholder: "Personality & Skills Map" },
        about: { title: "Vision & Mission", description: "Driven by a passion for synthesizing seemingly disparate fields.", cta: "Get in Touch ↓" },
        contact: { venture_name: "Collaborate", title: "Contact Us", name_label: "Name", name_placeholder: "Your Name", email_label: "Email", email_placeholder: "you@example.com", message_label: "Message", message_placeholder: "Tell me about your idea...", cta: "Send Message", success_message: "Message sent successfully! I'll be in touch soon." }
      },
      fr: {
        home: { title: "BETTARA", subtitle: "Connecter les gens", description: "À soi. À l'autre. Aux publics.", cta: "Commencer l'exploration" },
        present: { title: "Présent, pas pressé", description: "L'art de la présence consciente et sans hâte.", cta: "Plongée profonde →", placeholder: "Espace réservé pour l'actif visuel" },
        passerelles: { venture_name: "Entreprise 2", title: "Passerelles", description: "Passerelles se consacre à forger des connexions stratégiques.", cta: "Voir les projets →", placeholder: "Visuel de pont stratégique" },
        facettes: { title: "Facettes", description: "Une célébration du professionnel aux multiples facettes.", cta: "Découvrir les facettes →", placeholder: "Carte de personnalité et compétences" },
        about: { title: "Vision et mission", description: "Animé par une passion pour la synthèse de domaines apparemment disparates.", cta: "Entrer en contact ↓" },
        contact: { venture_name: "Collaborer", title: "Nous contacter", name_label: "Nom", name_placeholder: "Votre nom", email_label: "Courriel", email_placeholder: "vous@exemple.com", message_label: "Message", message_placeholder: "Parlez-moi de votre idée...", cta: "Envoyer le message", success_message: "Message envoyé avec succès ! Je vous contacterai bientôt." }
      }
    };
    await contentCollection.insertOne(defaultContent);
    console.log('✓ Default content created');
  }
  
  // Check if users exist
  const userCount = await usersCollection.countDocuments();
  if (userCount === 0) {
    console.log('Initializing users collection...');
    const hashedPassword = await bcrypt.hash('bettara123', 10);
    const defaultUser = {
      id: uuidv4(),
      username: 'bettara',
      password: hashedPassword
    };
    await usersCollection.insertOne(defaultUser);
    console.log('✓ Default admin user created');
  }
}

// Ensure uploads directory exists
fs.ensureDirSync(path.join(__dirname, 'public', 'uploads'));

// Middleware setup
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecuresecretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public'), {
  index: false
}));

// --- AUTHENTICATION ---
const requireAuth = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }
    res.redirect('/login');
  }
};

// Login routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt for:', username);
  
  try {
    const user = await usersCollection.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { username: user.username, id: user.id };
      console.log('Login successful');
      
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/login?error=1');
        }
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

// Protect admin routes
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

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

// --- API ROUTES ---

// Get content
app.get('/api/content', async (req, res) => {
  const { section, lang } = req.query;
  
  try {
    const contentDoc = await contentCollection.findOne({ _id: 'content' });
    
    if (!contentDoc) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    // If section and lang are specified, return specific section content (for admin)
    if (section && lang) {
      console.log(`Admin requesting: section=${section}, lang=${lang}`);
      const sectionContent = contentDoc[lang]?.[section] || {};
      return res.json(sectionContent);
    }
    
    // Otherwise, return all content for the current language (for frontend)
    const currentLang = req.cookies.lang || 'en';
    console.log('Frontend requesting, language:', currentLang);
    res.json(contentDoc[currentLang] || contentDoc.en);
  } catch (error) {
    console.error('Error reading content:', error);
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// Save content (Admin only)
app.post('/api/content', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { section, lang } = req.body;
    
    console.log('========== SAVE CONTENT REQUEST ==========');
    console.log('Section:', section, 'Language:', lang);
    console.log('User:', req.session.user.username);
    
    // Get current content document
    const contentDoc = await contentCollection.findOne({ _id: 'content' });
    
    if (!contentDoc) {
      return res.status(404).json({ success: false, error: 'Content document not found' });
    }
    
    // Ensure structure exists
    if (!contentDoc[lang]) {
      contentDoc[lang] = {};
    }
    if (!contentDoc[lang][section]) {
      contentDoc[lang][section] = {};
    }
    
    // Update fields
    let updatedFields = [];
    for (const key in req.body) {
      if (!['section', 'lang'].includes(key)) {
        contentDoc[lang][section][key] = req.body[key];
        updatedFields.push(key);
        console.log(`✓ Updated ${key}`);
      }
    }
    
    // Handle image upload
    if (req.file) {
      contentDoc[lang][section].imageUrl = `/uploads/${req.file.filename}`;
      updatedFields.push('imageUrl');
      console.log('✓ Image uploaded:', req.file.filename);
    }
    
    // Save to MongoDB
    const result = await contentCollection.updateOne(
      { _id: 'content' },
      { $set: { [lang]: contentDoc[lang] } }
    );
    
    console.log('MongoDB update result:', result.modifiedCount, 'documents modified');
    console.log('✓ Content saved to MongoDB');
    console.log('========== SAVE SUCCESSFUL ==========');
    
    res.json({ 
      success: true, 
      content: contentDoc[lang][section], 
      updatedFields 
    });
    
  } catch (error) {
    console.error('========== SAVE FAILED ==========');
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- USER MANAGEMENT API ROUTES ---

// Get all users
app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const users = await usersCollection.find({}).toArray();
    const safeUsers = users.map(u => ({ id: u.id, username: u.username }));
    res.json({ success: true, users: safeUsers });
  } catch (error) {
    console.error('Error reading users:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add new user
app.post('/api/users', requireAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword
    };
    
    await usersCollection.insertOne(newUser);
    
    console.log('New user created:', username);
    res.json({ success: true, user: { id: newUser.id, username: newUser.username } });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete user
app.delete('/api/users/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (req.session.user.id === id) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }
    
    const userCount = await usersCollection.countDocuments();
    if (userCount === 1) {
      return res.status(400).json({ success: false, error: 'Cannot delete the last user' });
    }
    
    const result = await usersCollection.deleteOne({ id });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    console.log('User deleted:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Change password
app.put('/api/users/:id/password', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await usersCollection.updateOne(
      { id },
      { $set: { password: hashedPassword } }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    console.log('Password changed for user:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start server after connecting to database
connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ Admin login - username: bettara, password: bettara123`);
  });
});