require('dotenv').config();
const express = require('express'); // Re-deploy trigger

const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const axios = require('axios');
const nodemailer = require('nodemailer');
const http = require('http');
const { Server } = require('socket.io');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Helper for Pakistan Standard Time (PKT)
const getPKTDate = () => {
  const now = new Date();
  // Pakistan is UTC+5. 
  return new Date(now.getTime() + (5 * 60 * 60 * 1000));
};

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 2000;
const SECRET_KEY = 'Mediapp_Synced_Key_2026_Global'; // FORCED SYNC - DO NOT USE process.env

// Create HTTP server and Socket.IO instance
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Middleware Setup
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'frontend', 'views'));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const promoEmailEnabled = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);
const promoTransporter = promoEmailEnabled
  ? nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  })
  : null;

// Multer setup for file uploads (general - medicines etc might still need local or separate setup)
const uploadsPath = process.env.VERCEL ? path.join('/tmp', 'Uploads') : path.join(__dirname, 'Uploads');
try {
  if (!fs.existsSync(uploadsPath)) {
    fs.mkdirSync(uploadsPath, { recursive: true });
  }
} catch (err) {
  console.warn('Could not create uploads directory:', err.message);
}

const storage1 = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsPath),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload1 = multer({ storage: storage1 });

// Multer setup for profile image uploads using Cloudinary
const profileStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'mediapp/profiles',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'jfif'],
    transformation: [{ width: 500, height: 500, crop: 'limit' }],
  },
});

const medicineStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'mediapp/medicines',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'jfif'],
  },
});

// Multer setup for chat media uploads using Cloudinary
const chatStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'mediapp/chat',
    // Removed allowed_formats to avoid conflicts with resource_type: 'auto' (especially for voice)
    resource_type: 'auto',
  },
});

const uploadProfile = multer({ storage: profileStorage });
const uploadMedicine = multer({ storage: medicineStorage });
const uploadChat = multer({ storage: chatStorage });

// MongoDB Connection



const uri = process.env.MONGODB_URI || "mongodb+srv://teammediapp:Aqee201@mediapp.hbuyqtw.mongodb.net/mediApp?retryWrites=true&w=majority&appName=MediApp";

async function connectDB() {
  try {
    await mongoose.connect(uri, {
      serverApi: {
        version: '1', // Matches ServerApiVersion.v1
        strict: true,
        deprecationErrors: true,
      },
      connectTimeoutMS: 30000, // 30 seconds
      socketTimeoutMS: 45000,  // 45 seconds
    });

    // Wait for the connection to be established
    await new Promise((resolve, reject) => {
      mongoose.connection.once('open', () => {
        console.log("Successfully connected to MongoDB via Mongoose!");
        resolve();
      });
      mongoose.connection.on('error', (err) => {
        console.error("MongoDB connection error:", err);
        reject(err);
      });
    });

    // Optional: Ping to verify connectivity
    try {
      await mongoose.connection.db.command({ ping: 1 });
      console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (pingError) {
      console.error("Ping failed, but connection is established:", pingError.message);
      // Continue even if ping fails, as connection is open
    }
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
    process.exit(1); // Exit the process on connection failure
  }
}



// ... (rest of your schemas and routes remain unchanged until the server start)

// Schemas and Models

// Settings Schema
const SettingsSchema = new mongoose.Schema({
  lowStockThreshold: { type: Number, default: 10 },
  expiryAlertDays: { type: Number, default: 30 },
  emailNotifications: { type: Boolean, default: true },
  inAppNotifications: { type: Boolean, default: true },
  defaultUserRole: { type: String, default: 'user' },
  currency: { type: String, default: 'PKR' },
  dateFormat: { type: String, default: 'DD/MM/YYYY' },
  apiKey: { type: String, default: '' },
  darkMode: { type: Boolean, default: false },
});
const Settings = mongoose.models.Settings || mongoose.model('Settings', SettingsSchema);

// User Schema
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, default: uuidv4 },
  firstName: { type: String, required: true },
  lastName: { type: String, default: '' },
  CNICNo: { type: String, default: '' },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profileImage: { type: String, default: null },
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: getPKTDate },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  location: { type: String, default: '' },
  dob: { type: String, default: '' },
  promoOptIn: { type: Boolean, default: true },
  promoLastSentAt: { type: Date, default: null },
  promoNextAt: { type: Date, default: null },
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Category Schema
const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  name: { type: String, required: true, unique: true },
});
const Category = mongoose.models.Category || mongoose.model('Category', CategorySchema);

// Medicine Schema
const MedicineSchema = new mongoose.Schema({
  name: { type: String, required: true },
  manufacturer: { type: String, required: true },
  expiryDate: { type: Date, required: true },
  price: { type: Number, required: true },
  dosage: { type: String },
  quantity: { type: Number, required: true },
  image: { type: String },
  category: { type: String, required: true },
  medicineType: { type: String, enum: ['Tablet', 'Capsule', 'Syrup'], required: true },
  dosesPerUnit: { type: Number, default: 1 },
  remainingDoses: { type: Number, default: 0 },
  likes: { type: [String], default: [] },
  description: { type: String, default: '' }, // New field for description
  description: { type: String, default: '' }, // New field for description
});
const Medicine = mongoose.models.Medicine || mongoose.model('Medicine', MedicineSchema);

// Order Schema
const OrderSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  shippingEmail: { type: String, required: true },
  billingEmail: { type: String },
  shippingAddress: { firstName: String, lastName: String, streetAddress: String, phoneNumber: String },
  billingAddress: { firstName: String, lastName: String, streetAddress: String, phoneNumber: String },
  shippingMethod: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  cartItems: { type: Array, default: [] },
  shippingFee: { type: Number, required: true },
  orderTotal: { type: Number, required: true },
  location: { latitude: Number, longitude: Number },
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'shipped', 'delivered', 'cancelled', 'completed'], default: 'pending' },
  stockReserved: { type: Boolean, default: false },
  date: { type: Date, default: getPKTDate },
  transactionId: { type: String, default: null },
  paymentStatus: { type: String, enum: ['paid', 'unpaid'], default: 'unpaid' },
  statusUpdateHistory: [{ status: String, timestamp: { type: Date, default: getPKTDate } }],
  statusUpdateHistory: [{ status: String, timestamp: { type: Date, default: Date.now } }],
});
const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);

// Cart Schema
const CartSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  cart: { type: Array, default: [] },
  cart: { type: Array, default: [] },
});
const Cart = mongoose.models.Cart || mongoose.model('Cart', CartSchema);

const buildMedicineMap = (medicines) => {
  const map = new Map();
  for (const med of medicines) {
    map.set(String(med._id), med);
  }
  return map;
};

const sanitizeCartItems = (cartItems, medMap) => {
  const cleaned = [];
  for (const item of cartItems || []) {
    const id = String(item._id || item.id || '');
    const med = medMap.get(id);
    if (!med) continue;
    const availableStock = Number(med.quantity || 0);
    if (availableStock <= 0) continue;
    const cartQty = Math.max(0, Number(item.cartQuantity || 0));
    const finalQty = Math.min(cartQty, availableStock);
    if (finalQty <= 0) continue;
    cleaned.push({
      ...item,
      _id: item._id || med._id,
      availableStock,
      cartQuantity: finalQty,
    });
  }
  return cleaned;
};

const refreshCartDocument = async (cartDoc) => {
  if (!cartDoc || !Array.isArray(cartDoc.cart)) return;
  const ids = cartDoc.cart.map((i) => i._id || i.id).filter(Boolean).map((id) => String(id));
  const medicines = ids.length ? await Medicine.find({ _id: { $in: ids } }).select('quantity') : [];
  const medMap = buildMedicineMap(medicines);
  const cleaned = sanitizeCartItems(cartDoc.cart, medMap);
  const changed =
    cleaned.length !== cartDoc.cart.length ||
    cleaned.some((c, idx) => c.cartQuantity !== cartDoc.cart[idx]?.cartQuantity || c.availableStock !== cartDoc.cart[idx]?.availableStock);
  if (changed) {
    cartDoc.cart = cleaned;
    await cartDoc.save();
  }
};

const pruneCartsForMedicines = async (medicineIds) => {
  const ids = (medicineIds || []).map((id) => String(id)).filter(Boolean);
  if (!ids.length) return;
  const carts = await Cart.find({
    $or: [
      { 'cart._id': { $in: ids } },
      { 'cart.id': { $in: ids } },
    ],
  });
  for (const cart of carts) {
    await refreshCartDocument(cart);
  }
};

const releaseReservedStock = async (order) => {
  if (!order || !order.stockReserved) return [];
  const affectedIds = [];
  for (const item of order.cartItems || []) {
    const medicineValue = item._id || item.id;
    if (!medicineValue) continue;
    const medicine = await Medicine.findById(medicineValue);
    if (!medicine) continue;
    const qty = Number(item.cartQuantity || 0);
    medicine.quantity = Math.max(0, Number(medicine.quantity || 0) + qty);
    await medicine.save();
    affectedIds.push(medicine._id);
  }
  order.stockReserved = false;
  return affectedIds;
};

const rejectOrderWithReason = async (order, reason = 'rejected') => {
  if (!order) return [];
  const affectedIds = await releaseReservedStock(order);
  order.status = 'rejected';
  order.paymentStatus = 'unpaid';
  order.statusUpdateHistory = order.statusUpdateHistory || [];
  order.statusUpdateHistory.push({ status: 'rejected', timestamp: getPKTDate(), reason });
  await order.save();
  return affectedIds;
};

const autoRejectConflictingOrders = async (acceptedOrder) => {
  if (!acceptedOrder) return;
  const otherOrders = await Order.find({
    _id: { $ne: acceptedOrder._id },
    status: 'pending',
  }).lean();

  if (!otherOrders.length) return;

  const affectedIds = new Set();
  for (const order of otherOrders) {
    let hasShortage = false;
    for (const item of order.cartItems || []) {
      const medicineValue = item._id || item.id;
      if (!medicineValue) continue;
      const medicine = await Medicine.findById(medicineValue).select('quantity');
      const available = Number(medicine?.quantity || 0);
      const requested = Number(item.cartQuantity || 0);
      if (available < requested) {
        hasShortage = true;
        break;
      }
    }
    if (hasShortage) {
      const orderDoc = await Order.findById(order._id);
      if (orderDoc) {
        const released = await rejectOrderWithReason(orderDoc, 'auto_reject_no_stock');
        released.forEach((id) => affectedIds.add(String(id)));
      }
    }
  }

  if (affectedIds.size) {
    await pruneCartsForMedicines(Array.from(affectedIds));
  }
};

// In-Person Sale Schema
const InPersonSaleSchema = new mongoose.Schema({
  medicineId: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine', required: true },
  medicineName: { type: String, required: true },
  quantitySold: { type: Number, required: true },
  unitType: { type: String, required: true },
  saleDate: { type: Date, default: getPKTDate },
  customerName: { type: String },
  customerContact: { type: String },
  adminId: { type: String, required: true },
  totalAmount: { type: Number, required: true },
  adminId: { type: String, required: true },
  totalAmount: { type: Number, required: true },
});
const InPersonSale = mongoose.models.InPersonSale || mongoose.model('InPersonSale', InPersonSaleSchema);

const PROMO_TEMPLATES = [
  {
    subject: 'MediApp: Simple habits, stronger health',
    headline: 'A small routine can make a big difference',
    body: [
      'Drink water first thing in the morning.',
      'Add 10–20 minutes of light movement.',
      'Keep medicines organized and on time.',
    ],
    cta: 'Open MediApp',
  },
  {
    subject: 'MediApp Care: Feeling under the weather?',
    headline: 'Get guidance and medicine options faster',
    body: [
      'Check symptoms and safe self‑care tips.',
      'See medicines available in your local store.',
      'Order quickly with delivery tracking.',
    ],
    cta: 'Check Symptoms',
  },
  {
    subject: 'MediApp Wellness: Your health, simplified',
    headline: 'Stay consistent with daily health basics',
    body: [
      'Sleep 7–8 hours for better recovery.',
      'Eat balanced meals with protein + fiber.',
      'Set medicine reminders in one place.',
    ],
    cta: 'Explore MediApp',
  },
];

const getNextPromoDate = (fromDate = new Date()) => {
  const minMs = 48 * 60 * 60 * 1000;
  const maxMs = 72 * 60 * 60 * 1000;
  const delta = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  return new Date(fromDate.getTime() + delta);
};

const buildPromoEmail = (user, template) => {
  const appUrl = process.env.PROMO_APP_URL || process.env.APP_PUBLIC_URL || 'https://mediapp.app';
  const name = user?.firstName || 'there';
  const listItems = template.body.map((line) => `<li style="margin-bottom:8px;">${line}</li>`).join('');
  const html = `
  <div style="font-family:Arial,sans-serif;color:#0f172a;background:#f8fafc;padding:24px;">
    <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:14px;padding:24px;border:1px solid #e2e8f0;">
      <h2 style="margin:0 0 8px 0;color:#1d4ed8;">${template.headline}</h2>
      <p style="margin:0 0 16px 0;color:#334155;">Hi ${name},</p>
      <ul style="padding-left:18px;margin:0 0 16px 0;color:#334155;">${listItems}</ul>
      <a href="${appUrl}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:10px 16px;border-radius:10px;font-weight:bold;">
        ${template.cta}
      </a>
      <p style="margin-top:18px;color:#64748b;font-size:12px;">
        You received this because you’re a MediApp user.
      </p>
    </div>
  </div>`;
  const text = `Hi ${name},\n\n${template.body.join('\n')}\n\n${template.cta}: ${appUrl}\n\n— MediApp`;
  return { subject: template.subject, html, text };
};

const isPromoAuthorized = (req) => {
  const configuredSecret = process.env.PROMO_CRON_SECRET || '';
  const incomingSecret = req.headers['x-cron-secret'] || req.query.secret || '';
  const vercelCronHeader = req.headers['x-vercel-cron'];
  const isVercelCron = String(vercelCronHeader || '').toLowerCase() === '1' || String(vercelCronHeader || '').toLowerCase() === 'true';
  if (!configuredSecret) return isVercelCron;
  return incomingSecret === configuredSecret || isVercelCron;
};

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  walletNumber: { type: String, required: true },
  walletName: { type: String, required: true },
  transactionID: { type: String, required: true },
  depositAmount: { type: Number, required: true },
  status: { type: String, enum: ['Accepted', 'Rejected', 'Pending'], default: 'Pending' },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
  createdAt: { type: Date, default: getPKTDate },
});
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

// Middleware to Fetch Settings
app.use(async (req, res, next) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
      await settings.save();
    }
    res.locals.settings = settings.toObject();
  } catch (err) {
    console.error('Error fetching settings:', err);
    res.locals.settings = {
      lowStockThreshold: 10,
      expiryAlertDays: 30,
      emailNotifications: true,
      inAppNotifications: true,
      defaultUserRole: 'user',
      currency: 'PKR',
      dateFormat: 'DD/MM/YYYY',
      apiKey: '',
      darkMode: false,
    };
  }
  next();
});

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Authorization required' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ email: decoded.email.toLowerCase() });
    if (!user) return res.status(401).json({ message: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    console.log('--- AUTH ERROR START ---');
    console.error('authMiddleware error:', err.message);
    console.log('Token received:', req.headers.authorization ? 'EXISTS' : 'MISSING');
    console.log('SECRET_KEY used:', SECRET_KEY);
    console.log('--- AUTH ERROR END ---');
    return res.status(401).json({
      message: 'Invalid token',
      error: err.message,
      server_type: 'MEDICINE_BACKEND_LATEST',
      auth_error: true
    });
  }
};

const authMiddlewarePage = async (req, res, next) => {
  const token = req.query.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.redirect('/login.html');
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ email: decoded.email.toLowerCase() });
    if (!user) return res.redirect('/login.html');
    req.user = user;
    next();
  } catch (err) {
    return res.redirect('/login.html');
  }
};

const authAdminPage = async (req, res, next) => {
  const token = req.query.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  console.log('authAdminPage: Token received:', token);
  if (!token) {
    console.error('authAdminPage: No token provided');
    return res.redirect('/login.html?error=No token provided');
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('authAdminPage: Token decoded:', decoded);
    const user = await User.findOne({ email: decoded.email.toLowerCase() });
    if (!user) {
      console.error('authAdminPage: User not found for email:', decoded.email);
      return res.redirect('/login.html?error=User not found');
    }
    if (user.role !== 'admin') {
      console.error('authAdminPage: Non-admin user attempted access:', user.email);
      return res.status(403).send('Admin access required');
    }
    req.user = user;
    next();
  } catch (err) {
    console.error('authAdminPage: Token verification failed:', err.message);
    return res.redirect('/login.html?error=Invalid token');
  }
};

// Routes

app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.post('/api/auth/signup', uploadProfile.single('profileImage'), async (req, res) => {
  let { firstName, lastName, CNICNo, email, password } = req.body;
  const profileImage = req.file ? req.file.path : null;
  if (!firstName || !email || !password) return res.status(400).json({ message: 'Required fields missing' });
  email = email.toLowerCase();
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = new User({
      id: uuidv4(),
      firstName,
      lastName: lastName || '',
      CNICNo: CNICNo || '',
      email,
      password: hashedPassword,
      profileImage,
      role: 'user',
      createdAt: new Date().toISOString(),
    });
    await newUser.save();
    const token = jwt.sign({ email, role: 'user' }, SECRET_KEY);
    const { password: pwd, ...userWithoutPassword } = newUser.toObject();
    res.status(201).json({ message: 'User created', token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  let { email, password } = req.body;
  email = email.toLowerCase();
  try {
    const user = await User.findOne({ email });
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ email, role: user.role }, SECRET_KEY);
    const { password: pwd, ...userWithoutPassword } = user.toObject();
    res.json({ message: 'Login successful', token, role: user.role, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/auth/profile', authMiddleware, (req, res) => {
  const { password, ...userWithoutPassword } = req.user.toObject();
  res.json({ user: userWithoutPassword });
});

app.put('/api/auth/update', authMiddleware, uploadProfile.single('profileImage'), async (req, res) => {
  try {
    const user = req.user;
    const { firstName, lastName, CNICNo, phone, address, dob } = req.body;
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (CNICNo) user.CNICNo = CNICNo;
    if (phone) user.phone = phone;
    if (address) user.address = address;
    if (dob) user.dob = dob;
    if (req.file) user.profileImage = req.file.path;
    await user.save();
    const { password, ...userWithoutPassword } = user.toObject();
    res.json({ message: 'Profile updated successfully', user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.put('/api/promotions/opt-in', authMiddleware, async (req, res) => {
  try {
    const raw = req.body?.promoOptIn ?? req.body?.optIn;
    if (raw === undefined) {
      return res.status(400).json({ message: 'promoOptIn is required' });
    }
    const flag = String(raw).toLowerCase() === 'true';
    req.user.promoOptIn = flag;
    if (flag && !req.user.promoNextAt) {
      req.user.promoNextAt = getNextPromoDate(new Date());
    }
    if (!flag) {
      req.user.promoNextAt = null;
    }
    await req.user.save();
    const { password, ...userWithoutPassword } = req.user.toObject();
    res.json({ message: 'Promo preference updated', user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  try {
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});



app.put('/api/users/:id/password', authMiddleware, async (req, res) => {
  const { newPassword, adminPassword } = req.body;
  const userId = req.params.id;
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  try {
    if (!bcrypt.compareSync(adminPassword, req.user.password)) return res.status(401).json({ message: 'Invalid admin password' });
    const user = await User.findOne({ id: userId });
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/admin/users', authAdminPage, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.render('users', {
      users,
      user: req.user,
      token: req.query.token,
      currentPath: req.path,
      message: req.query.message || null,
      error: req.query.error || null,
    });
  } catch (err) {
    console.error(err);
    res.render('users', {
      users: [],
      user: req.user,
      token: req.query.token,
      currentPath: req.path,
      message: null,
      error: 'Server error',
    });
  }
});

app.post('/admin/users/:id/delete', authAdminPage, async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await User.findOne({ id: userId });
    if (!user) return res.redirect('/admin/users?error=User not found&token=' + req.query.token);
    if (user.role === 'admin') return res.redirect('/admin/users?error=Cannot delete admin users&token=' + req.query.token);
    await User.deleteOne({ id: userId });
    res.redirect('/admin/users?message=User deleted successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/users?error=Error deleting user&token=' + req.query.token);
  }
});

app.get('/admin/users/:id/change-password', authAdminPage, async (req, res) => {
  try {
    const userToChange = await User.findOne({ id: req.params.id });
    if (!userToChange) return res.redirect('/admin/users?error=User not found&token=' + req.query.token);
    res.render('change-password', {
      user: req.user,
      userToChange,
      token: req.query.token,
      message: req.query.message || null,
      error: req.query.error || null,
    });
  } catch (err) {
    console.error(err);
    res.redirect('/admin/users?error=Server error&token=' + req.query.token);
  }
});

app.post('/admin/users/:id/change-password', authAdminPage, async (req, res) => {
  try {
    const { newPassword, adminPassword } = req.body;
    const userId = req.params.id;
    if (!newPassword || !adminPassword) return res.redirect(`/admin/users/${userId}/change-password?error=Please fill all fields&token=${req.query.token}`);
    if (!bcrypt.compareSync(adminPassword, req.user.password)) return res.redirect(`/admin/users/${userId}/change-password?error=Invalid admin password&token=${req.query.token}`);
    const userToChange = await User.findOne({ id: userId });
    if (!userToChange) return res.redirect('/admin/users?error=User not found&token=' + req.query.token);
    userToChange.password = bcrypt.hashSync(newPassword, 10);
    await userToChange.save();
    res.redirect('/admin/users?message=Password updated successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect(`/admin/users/${req.params.id}/change-password?error=Server error&token=${req.query.token}`);
  }
});

app.get('/categories', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (err) {
    console.error('API /categories error:', err);
    res.status(500).json({ error: 'Server error fetching categories', details: err.message });
  }
});

app.get('/medicines', async (req, res) => {
  try {
    let userId = null;
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = await User.findOne({ email: decoded.email.toLowerCase() });
        if (user) userId = user.id;
      } catch (err) { }
    }
    const medicines = await Medicine.find().sort({ name: 1 });
    const result = medicines.map((med) => {
      const medObj = med.toObject();
      medObj.liked = userId ? med.likes.includes(userId) : false;
      return medObj;
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/medicines/:medicineId/like', authMiddleware, async (req, res) => {
  try {
    const medicineId = req.params.medicineId;
    const medicine = await Medicine.findById(medicineId);
    if (!medicine) return res.status(404).json({ error: 'Medicine not found' });
    const userId = req.user.id;
    const index = medicine.likes.indexOf(userId);
    if (index > -1) medicine.likes.splice(index, 1);
    else medicine.likes.push(userId);
    await medicine.save();
    const liked = medicine.likes.includes(userId);
    res.json({ liked, likesCount: medicine.likes.length });
  } catch (err) {
    console.error('Error toggling like:', err);
    res.status(500).json({ error: 'Server error toggling like', details: err.message });
  }
});

app.get('/api/cart', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const cart = await Cart.findOne({ userId });
    if (!cart || !Array.isArray(cart.cart)) {
      return res.json({ cartItems: [] });
    }
    const ids = cart.cart.map((i) => i._id || i.id).filter(Boolean).map((id) => String(id));
    const medicines = ids.length ? await Medicine.find({ _id: { $in: ids } }).select('quantity') : [];
    const medMap = buildMedicineMap(medicines);
    const cleaned = sanitizeCartItems(cart.cart, medMap);
    if (cleaned.length !== cart.cart.length) {
      cart.cart = cleaned;
      await cart.save();
    }
    res.json({ cartItems: cleaned });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cart', async (req, res) => {
  try {
    const { userId, cart } = req.body;
    if (!userId || !Array.isArray(cart)) return res.status(400).json({ error: 'Invalid request data' });
    const ids = cart.map((i) => i._id || i.id).filter(Boolean).map((id) => String(id));
    const medicines = ids.length ? await Medicine.find({ _id: { $in: ids } }).select('quantity') : [];
    const medMap = buildMedicineMap(medicines);
    const cleaned = sanitizeCartItems(cart, medMap);
    let userCart = await Cart.findOne({ userId });
    if (userCart) {
      userCart.cart = cleaned;
      await userCart.save();
    } else {
      userCart = new Cart({ userId, cart: cleaned });
      await userCart.save();
    }
    res.json({ message: 'Cart saved successfully', cart: userCart.cart });
  } catch (err) {
    console.error('Error saving cart:', err);
    res.status(500).json({ error: 'Failed to save cart', details: err.message });
  }
});

app.get('/api/order', async (req, res) => {
  try {
    const { userId } = req.query;
    console.log(`[API] Fetching orders for userId: ${userId}`);
    if (!userId || userId === 'undefined') return res.status(400).json({ error: 'Missing or invalid userId' });
    const orders = await Order.find({ userId }).sort({ date: -1 });
    console.log(`[API] Found ${orders.length} orders for ${userId}`);
    res.json({ orders });
  } catch (err) {
    console.error(`[API ERROR] GET /api/order:`, err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/order/:id/cancel', async (req, res) => {
  try {
    const { userId } = req.body || {};
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (userId && order.userId !== userId) {
      return res.status(403).json({ error: 'Not authorized to cancel this order' });
    }
    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Only pending orders can be cancelled' });
    }

    const affectedIds = await releaseReservedStock(order);
    order.status = 'cancelled';
    order.paymentStatus = 'unpaid';
    order.statusUpdateHistory = order.statusUpdateHistory || [];
    order.statusUpdateHistory.push({ status: 'cancelled', timestamp: getPKTDate() });
    await order.save();
    if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
    await createNotification({
      userId: order.userId,
      title: 'Order Cancelled',
      message: `Your order ${order._id} has been cancelled.`,
      type: 'order',
      relatedId: order._id,
    });
    await sendPushToUser(order.userId, {
      title: 'Order Cancelled',
      body: `Your order ${order._id} has been cancelled.`,
      data: { type: 'order', orderId: String(order._id) },
    });

    res.json({ message: 'Order cancelled', order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to cancel order' });
  }
});

app.post('/api/order', async (req, res) => {
  try {
    const { userId, shippingEmail, billingEmail, shippingAddress, billingAddress, shippingMethod, paymentMethod, cartItems, shippingFee, orderTotal, location } = req.body;
    if (!userId || !Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ error: 'Invalid order data' });
    }

    // Validate stock before creating order
    const ids = cartItems.map((i) => i._id || i.id).filter(Boolean).map((id) => String(id));
    const medicines = ids.length ? await Medicine.find({ _id: { $in: ids } }) : [];
    const medMap = buildMedicineMap(medicines);
    const insufficient = [];
    for (const item of cartItems) {
      const id = String(item._id || item.id || '');
      const med = medMap.get(id);
      const requested = Number(item.cartQuantity || 0);
      const available = Number(med?.quantity || 0);
      if (!med || available <= 0 || requested > available) {
        insufficient.push({
          _id: item._id || item.id,
          name: item.name,
          requested,
          available,
        });
      }
    }
    if (insufficient.length) {
      // Also clean user's cart to prevent stale quantities
      try {
        const userCart = await Cart.findOne({ userId });
        if (userCart) await refreshCartDocument(userCart);
      } catch (cartErr) {
        console.warn('Failed to clean cart after insufficient stock:', cartErr.message);
      }
      return res.status(409).json({
        error: 'Insufficient stock for one or more items',
        items: insufficient,
      });
    }

    // Reserve stock immediately (POS-style) so other carts update
    const affectedIds = [];
    for (const item of cartItems) {
      const id = String(item._id || item.id || '');
      const medicine = medMap.get(id);
      if (medicine) {
        medicine.quantity = Math.max(0, Number(medicine.quantity || 0) - Number(item.cartQuantity || 0));
        await medicine.save();
        affectedIds.push(medicine._id);
      }
    }
    if (affectedIds.length) {
      await pruneCartsForMedicines(affectedIds);
    }

    const newOrder = new Order({
      userId,
      shippingEmail,
      billingEmail,
      shippingAddress,
      billingAddress,
      shippingMethod,
      paymentMethod,
      cartItems,
      shippingFee,
      orderTotal,
      location,
      status: 'pending',
      stockReserved: true,
    });
    await newOrder.save();
    res.json({ message: 'Order placed successfully', order: newOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to place order' });
  }
});

  app.post('/admin/orders/:id/accept', authAdminPage, async (req, res) => {
    try {
      const order = await Order.findById(req.params.id);
      if (!order) return res.status(404).json({ error: 'Order not found' });

      // Stock validation before accepting (skip if already reserved)
      if (!order.stockReserved) {
        const shortages = [];
        for (let item of order.cartItems) {
          const medicine = await Medicine.findById(item._id || item.id);
          if (!medicine || medicine.quantity < (item.cartQuantity || 0)) {
            shortages.push({
              _id: item._id || item.id,
              name: item.name,
              requested: item.cartQuantity || 0,
              available: medicine ? medicine.quantity : 0,
            });
          }
        }
        if (shortages.length) {
          await rejectOrderWithReason(order, 'no_stock_on_accept');
          return res.status(409).json({ error: 'Insufficient stock', items: shortages });
        }
      }

      const previousStatus = order.status;
      order.status = 'accepted';
    // For COD, payment is not paid upon acceptance (paid upon delivery)
    const pm = (order.paymentMethod || '').toLowerCase();
    if (pm !== 'cash on delivery' && pm !== 'cod') {
      order.paymentStatus = 'paid';
    }
    order.statusUpdateHistory = order.statusUpdateHistory || [];
    order.statusUpdateHistory.push({ status: 'accepted', timestamp: new Date() });

    if (order.transactionId && order.paymentMethod.toLowerCase() === 'easypaisa') {
      const transaction = await Transaction.findById(order.transactionId);
      if (transaction && transaction.status !== 'Accepted') {
        transaction.status = 'Accepted';
        await transaction.save();
      }
    }

      // Only deduct inventory if the order was NOT already accepted and not reserved
      if (previousStatus === 'pending' && !order.stockReserved) {
        const affectedIds = [];
        for (let item of order.cartItems) {
          const medicine = await Medicine.findById(item._id || item.id);
          if (medicine) {
            const newQty = Math.max(0, medicine.quantity - (item.cartQuantity || 0));
            medicine.quantity = newQty;
            await medicine.save();
            affectedIds.push(medicine._id);
          }
        }
        order.stockReserved = true;
        await pruneCartsForMedicines(affectedIds);
      }

      await order.save();
      await autoRejectConflictingOrders(order);
      await createNotification({
        userId: order.userId,
        title: 'Order Accepted',
        message: `Your order ${order._id} has been accepted.`,
        type: 'order',
        relatedId: order._id,
      });
      await sendPushToUser(order.userId, {
        title: 'Order Accepted',
        body: `Your order ${order._id} has been accepted.`,
        data: { type: 'order', orderId: String(order._id) },
      });
    res.json({ message: 'Order accepted', order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to accept order' });
  }
});

app.post('/admin/orders/:id/reject', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.status === 'accepted' || order.status === 'shipped' || order.status === 'delivered' || order.status === 'completed') {
      return res.status(400).json({ error: 'Cannot reject an already processed order' });
    }
    const affectedIds = await releaseReservedStock(order);
    order.status = 'rejected';
    order.paymentStatus = 'unpaid';
    order.statusUpdateHistory = order.statusUpdateHistory || [];
    order.statusUpdateHistory.push({ status: 'rejected', timestamp: getPKTDate() });
    await order.save();
    if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
    await createNotification({
      userId: order.userId,
      title: 'Order Rejected',
      message: `Your order ${order._id} was rejected by admin.`,
      type: 'order',
      relatedId: order._id,
    });
    await sendPushToUser(order.userId, {
      title: 'Order Rejected',
      body: `Your order ${order._id} was rejected by admin.`,
      data: { type: 'order', orderId: String(order._id) },
    });
    res.json({ message: 'Order rejected', order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reject order' });
  }
});

app.get('/admin/dashboard', authAdminPage, async (req, res) => {
  try {
    const medicineCount = await Medicine.countDocuments();
    const userCount = await User.countDocuments();
    const orders = await Order.find().sort({ date: -1 });
    const expiryThresholdDays = 30;
    const now = new Date();
    const expiryThresholdDate = new Date(now);
    expiryThresholdDate.setDate(now.getDate() + expiryThresholdDays);
    const expiryMedicines = await Medicine.find({ expiryDate: { $lte: expiryThresholdDate, $gte: now } });
    const lowStockMedicines = await Medicine.find({ quantity: { $lte: res.locals.settings.lowStockThreshold } });

    const onlineOrders = await Order.find().sort({ date: -1 });
    const inPersonSales = await InPersonSale.find()
      .sort({ saleDate: -1 })
      .populate('medicineId', 'name price medicineType dosesPerUnit')
      .populate('adminId', 'firstName lastName profileImage');

    const formattedOnlineOrders = onlineOrders
      .map((order) => {
        const orderTotal = order.cartItems.reduce((sum, item) => sum + (item.price || 0) * (item.cartQuantity || 0), 0);
        return {
          _id: order._id,
          shippingEmail: order.shippingEmail || 'N/A',
          shippingAddress: order.shippingAddress || { firstName: 'Unknown', lastName: '', streetAddress: 'N/A', phoneNumber: 'N/A' },
          orderTotal: orderTotal || order.orderTotal || 0,
          paymentMethod: order.paymentMethod || 'N/A',
          paymentStatus: order.paymentStatus || 'unpaid',
          status: order.status || 'pending',
          date: order.date,
          cartItems: order.cartItems || [],
          statusUpdateHistory: order.statusUpdateHistory || [],
          transactionId: order.transactionId || '',
          shippingFee: order.shippingFee || 0,
          location: order.location || null,
        };
      })
      .filter((order) => order.orderTotal > 0);

    const filteredInPersonSales = inPersonSales.filter(
      (sale) =>
        sale.medicineId &&
        typeof sale.medicineId.price === 'number' &&
        typeof sale.quantitySold === 'number' &&
        typeof sale.totalAmount === 'number' &&
        sale.quantitySold > 0
    );

    const calculatePeriodTotals = (period) => {
      const filterDate = (item) => {
        const date = item.date ? new Date(item.date) : new Date(item.saleDate);
        if (period === 'daily') {
          return date.toDateString() === now.toDateString();
        } else if (period === 'weekly') {
          const oneWeekAgo = new Date(now);
          oneWeekAgo.setDate(now.getDate() - 7);
          return date >= oneWeekAgo && date <= now;
        } else if (period === 'fortnightly') {
          const fifteenDaysAgo = new Date(now);
          fifteenDaysAgo.setDate(now.getDate() - 15);
          return date >= fifteenDaysAgo && date <= now;
        } else if (period === 'monthly') {
          return date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
        } else if (period === 'yearly') {
          return date.getFullYear() === now.getFullYear();
        }
        return false;
      };

      const filteredOrders = formattedOnlineOrders.filter(filterDate);
      const filteredSales = filteredInPersonSales.filter(filterDate);
      const totalSales = filteredOrders.reduce((sum, order) => sum + (order.orderTotal || 0), 0) + filteredSales.reduce((sum, sale) => sum + (sale.totalAmount || 0), 0);
      const totalProfit = totalSales * 0.3;
      const totalOrders = filteredOrders.length + filteredSales.length;
      return { totalSales, totalProfit, totalOrders };
    };

    const dailyTotals = calculatePeriodTotals('daily');
    const weeklyTotals = calculatePeriodTotals('weekly');
    const fortnightlyTotals = calculatePeriodTotals('fortnightly');
    const monthlyTotals = calculatePeriodTotals('monthly');
    const yearlyTotals = calculatePeriodTotals('yearly');

    const totalSales = formattedOnlineOrders.reduce((sum, order) => sum + (order.orderTotal || 0), 0) + filteredInPersonSales.reduce((sum, sale) => sum + (sale.totalAmount || 0), 0);
    const totalProfit = totalSales * 0.3;

    res.render('dashboard', {
      medicineCount,
      userCount,
      orders,
      expiryMedicines,
      lowStockMedicines,
      onlineOrders: formattedOnlineOrders,
      inPersonSales: filteredInPersonSales,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/dashboard',
      dailyTotals: { sales: dailyTotals.totalSales.toFixed(2), profit: dailyTotals.totalProfit.toFixed(2), orders: dailyTotals.totalOrders },
      weeklyTotals: { sales: weeklyTotals.totalSales.toFixed(2), profit: weeklyTotals.totalProfit.toFixed(2), orders: weeklyTotals.totalOrders },
      fortnightlyTotals: { sales: fortnightlyTotals.totalSales.toFixed(2), profit: fortnightlyTotals.totalProfit.toFixed(2), orders: fortnightlyTotals.totalOrders },
      monthlyTotals: { sales: monthlyTotals.totalSales.toFixed(2), profit: monthlyTotals.totalProfit.toFixed(2), orders: monthlyTotals.totalOrders },
      yearlyTotals: { sales: yearlyTotals.totalSales.toFixed(2), profit: yearlyTotals.totalProfit.toFixed(2), orders: yearlyTotals.totalOrders },
      totalSales: totalSales.toFixed(2),
      totalProfit: totalProfit.toFixed(2),
    });
  } catch (err) {
    console.error(err);
    res.render('dashboard', {
      medicineCount: 0,
      userCount: 0,
      orders: [],
      expiryMedicines: [],
      lowStockMedicines: [],
      onlineOrders: [],
      inPersonSales: [],
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/dashboard',
      dailyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      weeklyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      fortnightlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      monthlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      yearlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      totalSales: '0.00',
      totalProfit: '0.00',
    });
  }
});

app.get('/admin/medicine-alerts', authAdminPage, async (req, res) => {
  try {
    const expiryThresholdDate = new Date();
    expiryThresholdDate.setDate(expiryThresholdDate.getDate() + res.locals.settings.expiryAlertDays);
    const expiryMedicines = await Medicine.find({ expiryDate: { $lte: expiryThresholdDate, $gte: new Date() } });
    const lowStockMedicines = await Medicine.find({ quantity: { $lte: res.locals.settings.lowStockThreshold } });
    res.render('medicine-alerts', {
      user: req.user,
      token: req.query.token,
      expiryMedicines,
      lowStockMedicines,
      defaultThreshold: res.locals.settings.lowStockThreshold,
      currentPath: '/admin/medicine-alerts',
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/admin/orders', authAdminPage, async (req, res) => {
  try {
    const orders = await Order.find().sort({ date: -1 });
    const pendingOrders = await Order.find({ status: 'pending' });
    res.render('orders', { orders, pendingOrders, user: req.user, token: req.query.token, currentPath: '/admin/orders' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/admin/add-medicine', authAdminPage, async (req, res) => {
  try {
    const categories = await Category.find();
    res.render('add-medicine', {
      message: req.query.message || null,
      error: req.query.error || null,
      categories,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/add-medicine',
    });
  } catch (err) {
    console.error(err);
    res.render('add-medicine', {
      message: null,
      error: 'Failed to load categories',
      categories: [],
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/add-medicine',
    });
  }
});

app.post('/admin/add-medicine', authAdminPage, uploadMedicine.single('image'), async (req, res) => {
  try {
    let { name, manufacturer, expiryDate, price, dosage, quantity, category, newCategory, medicineType, dosesPerUnit, description } = req.body;
    const parsedQuantity = parseInt(quantity, 10);
    const parsedPrice = parseFloat(price);
    const parsedDosesPerUnit = parseInt(dosesPerUnit, 10) || 1;
    const expDate = new Date(expiryDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (expDate < today) {
      return res.render('add-medicine', {
        message: null,
        error: 'Expiry date cannot be in the past.',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    if (!/^\d+$/.test(quantity) || isNaN(parsedQuantity) || parsedQuantity < 1) {
      return res.render('add-medicine', {
        message: null,
        error: 'Quantity must be a positive integer (e.g., 1 or greater).',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      return res.render('add-medicine', {
        message: null,
        error: 'Price must be a positive number (e.g., greater than 0).',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    if (parsedDosesPerUnit < 1) {
      return res.render('add-medicine', {
        message: null,
        error: 'Doses per unit must be at least 1.',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    const image = req.file ? req.file.path : null;

    if (!['Tablet', 'Capsule', 'Syrup'].includes(medicineType)) {
      return res.render('add-medicine', {
        message: null,
        error: 'Invalid medicine type selected.',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    if (category === 'new') {
      if (!newCategory) {
        return res.render('add-medicine', {
          message: null,
          error: 'Please provide a new category name.',
          categories: await Category.find(),
          user: req.user,
          token: req.query.token,
          currentPath: '/admin/add-medicine',
        });
      }
      let existingCat = await Category.findOne({ name: newCategory.trim() });
      if (!existingCat) {
        existingCat = new Category({ name: newCategory.trim() });
        await existingCat.save();
      }
      category = existingCat.name;
    } else if (category) {
      const catDoc = await Category.findById(category);
      if (!catDoc) {
        return res.render('add-medicine', {
          message: null,
          error: 'Invalid category selected.',
          categories: await Category.find(),
          user: req.user,
          token: req.query.token,
          currentPath: '/admin/add-medicine',
        });
      }
      category = catDoc.name;
    } else {
      return res.render('add-medicine', {
        message: null,
        error: 'Please select a category.',
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }

    const existingMedicine = await Medicine.findOne({ name: new RegExp('^' + name.trim() + '$', 'i') });
    if (existingMedicine) {
      existingMedicine.quantity += parsedQuantity;
      existingMedicine.manufacturer = manufacturer;
      existingMedicine.expiryDate = expDate;
      existingMedicine.price = parsedPrice;
      existingMedicine.dosage = dosage;
      existingMedicine.medicineType = medicineType;
      existingMedicine.dosesPerUnit = parsedDosesPerUnit;
      if (image) existingMedicine.image = image;
      existingMedicine.category = category;
      existingMedicine.description = description || existingMedicine.description;
      await existingMedicine.save();
      return res.render('add-medicine', {
        message: 'Medicine already exists. Quantity and details updated successfully!',
        error: null,
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    } else {
      const newMedicine = new Medicine({
        name: name.trim(),
        manufacturer,
        expiryDate: expDate,
        price: parsedPrice,
        dosage,
        quantity: parsedQuantity,
        image,
        category,
        medicineType,
        dosesPerUnit: parsedDosesPerUnit,
        description,
      });
      await newMedicine.save();
      return res.render('add-medicine', {
        message: 'Medicine added successfully!',
        error: null,
        categories: await Category.find(),
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/add-medicine',
      });
    }
  } catch (err) {
    console.error(err);
    return res.render('add-medicine', {
      message: null,
      error: 'Failed to add medicine: ' + err.message,
      categories: await Category.find(),
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/add-medicine',
    });
  }
});

app.get('/admin/transactions', authAdminPage, async (req, res) => {
  try {
    const activeTab = req.query.tab || 'daily';
    const transactions = await Transaction.find().sort({ createdAt: -1 });

    const today = new Date();
    const filteredTransactions = transactions.filter((txn) => {
      const txnDate = new Date(txn.createdAt);
      if (activeTab === 'daily') {
        return txnDate.getDate() === today.getDate() && txnDate.getMonth() === today.getMonth() && txnDate.getFullYear() === today.getFullYear();
      } else if (activeTab === 'weekly') {
        const weekAgo = new Date();
        weekAgo.setDate(today.getDate() - 7);
        return txnDate >= weekAgo && txnDate <= today;
      } else if (activeTab === 'monthly') {
        return txnDate.getMonth() === today.getMonth() && txnDate.getFullYear() === today.getFullYear();
      }
      return false;
    });

    const totalAcceptedAmount = filteredTransactions
      .filter((txn) => txn.status === 'Accepted')
      .reduce((sum, txn) => sum + parseFloat(txn.depositAmount), 0)
      .toFixed(2);
    const totalTransactions = filteredTransactions.length;

    res.render('transaction', {
      filteredTransactions,
      activeTab,
      lastUpdated: new Date().toLocaleTimeString(),
      totalAcceptedAmount,
      totalTransactions,
      isLoading: false,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/transactions',
      message: req.query.message || null,
      error: req.query.error || null,
      getStatusBadgeClass: function (status) {
        switch (status.toLowerCase()) {
          case 'accepted':
            return 'badge-accepted';
          case 'rejected':
            return 'badge-rejected';
          case 'pending':
            return 'badge-pending';
          default:
            return 'badge-secondary';
        }
      },
    });
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.render('transaction', {
      filteredTransactions: [],
      activeTab: req.query.tab || 'daily',
      lastUpdated: new Date().toLocaleTimeString(),
      totalAcceptedAmount: '0.00',
      totalTransactions: 0,
      isLoading: false,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/transactions',
      message: null,
      error: 'Server error: Unable to fetch transactions',
      getStatusBadgeClass: function (status) {
        switch (status.toLowerCase()) {
          case 'accepted':
            return 'badge-accepted';
          case 'rejected':
            return 'badge-rejected';
          case 'pending':
            return 'badge-pending';
          default:
            return 'badge-secondary';
        }
      },
    });
  }
});

app.get('/admin/medicines', authAdminPage, async (req, res) => {
  try {
    let filter = {};
    const { category, medicineType } = req.query;
    if (category && category !== 'all') filter.category = category;
    if (medicineType && ['Tablet', 'Capsule', 'Syrup'].includes(medicineType)) filter.medicineType = medicineType;

    const medicines = await Medicine.find(filter).sort({ name: 1 });
    const categories = await Category.find();
    const selectedCategory = category || 'all';
    const selectedMedicineType = medicineType || null;

    res.render('list-medicines', {
      medicines,
      categories,
      selectedCategory,
      medicineType: selectedMedicineType,
      user: req.user,
      token: req.query.token,
      message: req.query.message || null,
      error: req.query.error || null,
      currentPath: '/admin/medicines',
    });
  } catch (err) {
    console.error('Error fetching medicines:', err);
    res.render('list-medicines', {
      medicines: [],
      categories: [],
      selectedCategory: 'all',
      medicineType: null,
      user: req.user,
      token: req.query.token,
      message: null,
      error: 'Error fetching medicines.',
      currentPath: '/admin/medicines',
    });
  }
});

app.post('/admin/update-stock', authAdminPage, async (req, res) => {
  try {
    const { items } = req.body;
    if (!Array.isArray(items) || !items.length) {
      console.warn('Invalid or empty items array:', items);
      return res.status(400).json({ success: false, error: 'Invalid items format', details: 'Items must be a non-empty array' });
    }

    for (const item of items) {
      const { id, quantity, unitType } = item;
      const qty = parseFloat(quantity);

      if (!id || isNaN(qty) || qty <= 0 || !unitType) {
        console.warn(`Invalid item data: ${JSON.stringify(item)}`);
        return res.status(400).json({ success: false, error: 'Invalid item data', details: `Item ${JSON.stringify(item)} has invalid id, quantity, or unitType` });
      }

      const medicine = await Medicine.findById(id);
      if (!medicine) {
        console.error(`Medicine not found for id ${id}`);
        return res.status(404).json({ success: false, error: `Medicine not found for id ${id}` });
      }

      if (!medicine.medicineType) {
        console.warn(`Medicine ${medicine.name} (id: ${id}) missing medicineType, setting default to 'Tablet'`);
        medicine.medicineType = 'Tablet';
      }

      if (unitType === 'Full' || medicine.medicineType === 'Syrup') {
        if (medicine.quantity < qty) {
          console.warn(`Insufficient stock for ${medicine.name}: requested ${qty}, available ${medicine.quantity}`);
          return res.status(400).json({ success: false, error: `Insufficient stock for ${medicine.name}`, available: medicine.quantity });
        }
        medicine.quantity -= qty;
      } else if (unitType === 'Dose') {
        const totalDoses = medicine.remainingDoses + qty;
        const unitsToDeduct = Math.floor(totalDoses / medicine.dosesPerUnit);
        const newRemainingDoses = totalDoses % medicine.dosesPerUnit;

        if (unitsToDeduct > 0) {
          if (medicine.quantity < unitsToDeduct) {
            console.warn(`Insufficient stock for ${medicine.name}: requested ${unitsToDeduct} units, available ${medicine.quantity}`);
            return res.status(400).json({ success: false, error: `Insufficient stock for ${medicine.name}`, available: medicine.quantity });
          }
          medicine.quantity -= unitsToDeduct;
        }
        medicine.remainingDoses = newRemainingDoses;
      }

      await medicine.save({ validateBeforeSave: true });
    }

    res.json({ success: true, message: 'Stock updated successfully' });
  } catch (err) {
    console.error('Stock update error:', err);
    res.status(500).json({ success: false, error: 'Stock update failed', details: err.message });
  }
});

app.get('/admin/edit-medicines', authAdminPage, async (req, res) => {
  try {
    const medicines = await Medicine.find().sort({ name: 1 });
    res.render('edit-medicines', { medicines, message: req.query.message || '', user: req.user, token: req.query.token, currentPath: '/admin/edit-medicines' });
  } catch (err) {
    console.error(err);
    res.render('edit-medicines', { medicines: [], message: 'Error fetching medicines for editing', user: req.user, token: req.query.token, currentPath: '/admin/edit-medicines' });
  }
});

app.get('/admin/medicines/:id/edit', authAdminPage, async (req, res) => {
  try {
    const medicine = await Medicine.findById(req.params.id);
    const categories = await Category.find();
    if (!medicine) return res.status(404).send('Medicine not found');
    res.render('edit-medicine', {
      medicine,
      message: req.query.message || '',
      error: req.query.error || null,
      categories,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/medicines/:id/edit',
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/admin/medicines/:id/edit', authAdminPage, uploadMedicine.single('image'), async (req, res) => {
  try {
    const { name, manufacturer, expiryDate, price, dosage, quantity, category, newCategory, medicineType, dosesPerUnit, description } = req.body;
    const medicine = await Medicine.findById(req.params.id);
    if (!medicine) return res.status(404).send('Medicine not found');

    const parsedQuantity = parseInt(quantity, 10);
    const parsedPrice = parseFloat(price);
    const parsedDosesPerUnit = parseInt(dosesPerUnit, 10) || 1;

    if (!/^\d+$/.test(quantity) || isNaN(parsedQuantity) || parsedQuantity < 0) {
      const categories = await Category.find();
      return res.render('edit-medicine', {
        medicine,
        message: null,
        error: 'Quantity must be a non-negative integer (e.g., 0 or greater).',
        categories,
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/medicines/:id/edit',
      });
    }

    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      const categories = await Category.find();
      return res.render('edit-medicine', {
        medicine,
        message: null,
        error: 'Price must be a positive number (e.g., greater than 0).',
        categories,
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/medicines/:id/edit',
      });
    }

    if (parsedDosesPerUnit < 1) {
      const categories = await Category.find();
      return res.render('edit-medicine', {
        medicine,
        message: null,
        error: 'Doses per unit must be at least 1.',
        categories,
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/medicines/:id/edit',
      });
    }

    if (!['Tablet', 'Capsule', 'Syrup'].includes(medicineType)) {
      const categories = await Category.find();
      return res.render('edit-medicine', {
        medicine,
        message: null,
        error: 'Invalid medicine type selected.',
        categories,
        user: req.user,
        token: req.query.token,
        currentPath: '/admin/medicines/:id/edit',
      });
    }

    medicine.name = name;
    medicine.manufacturer = manufacturer;
    medicine.expiryDate = new Date(expiryDate);
    medicine.price = parsedPrice;
    medicine.dosage = dosage;
    medicine.quantity = parsedQuantity;
    medicine.medicineType = medicineType;
    medicine.dosesPerUnit = parsedDosesPerUnit;
    if (req.file) medicine.image = req.file.path;
    medicine.description = description;

    let finalCategory = category;
    if (!category || category === 'new') {
      if (newCategory) {
        let existingCat = await Category.findOne({ name: newCategory.trim() });
        if (!existingCat) {
          existingCat = new Category({ name: newCategory.trim() });
          await existingCat.save();
        }
        finalCategory = existingCat.name;
      }
    }
    if (finalCategory) medicine.category = finalCategory;

    await medicine.save();
    const categories = await Category.find();
    res.render('edit-medicine', {
      medicine,
      message: 'Medicine updated successfully!',
      error: null,
      categories,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/medicines/:id/edit',
    });
  } catch (err) {
    console.error(err);
    const categories = await Category.find();
    res.render('edit-medicine', {
      medicine: await Medicine.findById(req.params.id),
      message: null,
      error: 'Failed to update medicine: ' + err.message,
      categories,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/medicines/:id/edit',
    });
  }
});

app.post('/admin/medicines/:id/delete', authAdminPage, async (req, res) => {
  try {
    const medicineId = req.params.id;
    const medicine = await Medicine.findById(medicineId);
    if (!medicine) return res.redirect('/admin/edit-medicines?error=Medicine not found&token=' + req.query.token);
    await Medicine.findByIdAndDelete(medicineId);
    res.redirect('/admin/edit-medicines?message=Medicine deleted successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/edit-medicines?error=Error deleting medicine&token=' + req.query.token);
  }
});

app.post('/admin/categories/delete', authAdminPage, async (req, res) => {
  try {
    const { categoryId } = req.body;
    if (!categoryId) return res.redirect('/admin/add-medicine?error=No category selected for deletion&token=' + req.query.token);
    const cat = await Category.findById(categoryId);
    if (!cat) return res.redirect('/admin/add-medicine?error=Category not found&token=' + req.query.token);
    const medicineCount = await Medicine.countDocuments({ category: cat.name });
    if (medicineCount > 0) return res.redirect('/admin/add-medicine?error=Cannot delete category with associated medicines&token=' + req.query.token);
    await Category.findByIdAndDelete(categoryId);
    res.redirect('/admin/add-medicine?message=Category deleted successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/add-medicine?error=Failed to delete category&token=' + req.query.token);
  }
});

app.post('/admin/categories/:id/delete', authAdminPage, async (req, res) => {
  try {
    const cat = await Category.findById(req.params.id);
    if (!cat) return res.redirect('/admin/add-medicine?error=Category not found&token=' + req.query.token);
    const medicineCount = await Medicine.countDocuments({ category: cat.name });
    if (medicineCount > 0) return res.redirect('/admin/add-medicine?error=Cannot delete category with associated medicines&token=' + req.query.token);
    await Category.findByIdAndDelete(req.params.id);
    res.redirect('/admin/add-medicine?message=Category deleted successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/add-medicine?error=Failed to delete category&token=' + req.query.token);
  }
});

app.post('/api/check-interactions', authMiddleware, async (req, res) => {
  try {
    const { ids = [], names = [] } = req.body;

    // 1) Fetch medicines from DB by ids or by name
    let meds = [];
    if (Array.isArray(ids) && ids.length) {
      meds = await Medicine.find({ _id: { $in: ids } });
    }
    if ((!meds || meds.length === 0) && Array.isArray(names) && names.length) {
      meds = await Promise.all(names.map(async (n) => {
        return await Medicine.findOne({ name: new RegExp('^' + n.trim() + '$', 'i') });
      }));
      meds = meds.filter(Boolean);
    }
    if (!meds || meds.length < 1) return res.json({ interactions: [], safe: true, message: 'No medicines found' });

    // 2) Lightweight interaction DB (extendable). Keyed by normalized medicine-name or active-ingredient.
    // NOTE: This is a sample; in production you should use a verified drug DB or clinical API.
    const interactionDB = [
      { pair: ['aspirin', 'warfarin'], severity: 'high', message: 'Increased bleeding risk.', alternatives: ['acetaminophen (paracetamol)'] },
      { pair: ['ibuprofen', 'lisinopril'], severity: 'moderate', message: 'NSAIDs may reduce antihypertensive effect.', alternatives: ['consult physician'] },
      { pair: ['metformin', 'contrast media'], severity: 'moderate', message: 'Risk of lactic acidosis (with iodinated contrast).', alternatives: ['talk to radiologist or physician'] },
      { pair: ['sildenafil', 'nitroglycerin'], severity: 'high', message: 'Severe hypotension risk (combination contraindicated).', alternatives: ['do not combine — urgent medical review'] },
      // Add custom pairs here...
    ];

    // Helper normalize function
    const normalize = (s) => (s || '').toString().toLowerCase().replace(/\s+/g, ' ').trim();

    // Build list of normalized identifiers to check: try name, manufacturer, dosage, description
    const medsNormalized = meds.map(m => ({
      id: m._id.toString(),
      name: normalize(m.name),
      manufacturer: normalize(m.manufacturer),
      dosage: normalize(m.dosage || ''),
      description: normalize(m.description || ''),
      raw: m
    }));

    // 3) Detect interactions by matching DB pairs against medicine names (naive matching).
    const found = [];
    for (let i = 0; i < medsNormalized.length; i++) {
      for (let j = i + 1; j < medsNormalized.length; j++) {
        const a = medsNormalized[i], b = medsNormalized[j];
        for (const entry of interactionDB) {
          const p0 = entry.pair[0], p1 = entry.pair[1];
          // match if either medicine name includes p0 and other includes p1 (or vice versa)
          const matchA = (a.name.includes(p0) || a.description.includes(p0) || a.dosage.includes(p0));
          const matchB = (b.name.includes(p1) || b.description.includes(p1) || b.dosage.includes(p1));
          const matchAlt = (a.name.includes(p1) || a.description.includes(p1) || a.dosage.includes(p1)) &&
            (b.name.includes(p0) || b.description.includes(p0) || b.dosage.includes(p0));
          if ((matchA && matchB) || matchAlt) {
            found.push({
              medicines: [a.raw, b.raw].map(m => ({ id: m._id, name: m.name, dosage: m.dosage || '', manufacturer: m.manufacturer || '' })),
              severity: entry.severity,
              message: entry.message,
              suggestions: entry.alternatives || []
            });
          }
        }
      }
    }

    const safe = found.length === 0;
    res.json({ interactions: found, safe });
  } catch (err) {
    console.error('Interaction check error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// ChatMessage Schema
const chatMessageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  type: { type: String, enum: ['text', 'image', 'voice', 'location', 'document'], required: true },
  content: { type: String, required: true },
  caption: { type: String, default: '' },
  timestamp: { type: Date, default: Date.now },
});
const ChatMessage = mongoose.models.ChatMessage || mongoose.model('ChatMessage', chatMessageSchema);

// AI Chat Session Schema
const aiChatSessionSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  title: { type: String, default: 'New Chat' },
  summary: { type: String, default: '' },
  summaryMessageCount: { type: Number, default: 0 },
  facts: {
    age: { type: String, default: '' },
    conditions: { type: [String], default: [] },
    allergies: { type: [String], default: [] },
    medications: { type: [String], default: [] },
  },
  lastSuggested: { type: [String], default: [] },
  messages: [
    {
      role: { type: String, enum: ['user', 'assistant'], required: true },
      content: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    },
  ],
}, { timestamps: true });
const AIChatSession = mongoose.models.AIChatSession || mongoose.model('AIChatSession', aiChatSessionSchema);

// Notification Schema
const NotificationSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, default: 'general' },
  read: { type: Boolean, default: false },
  relatedId: { type: String },
  date: { type: Date, default: Date.now }
});
const Notification = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);

const notificationTokenSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  userEmail: { type: String, default: '' },
  token: { type: String, required: true, unique: true },
  platform: { type: String, default: 'android' },
  updatedAt: { type: Date, default: Date.now },
});
const NotificationToken = mongoose.models.NotificationToken || mongoose.model('NotificationToken', notificationTokenSchema);

const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';

const chunkArray = (arr, size = 100) => {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
};

const sendPushNotifications = async (tokens, { title, body, data = {} }) => {
  const validTokens = (tokens || [])
    .filter((t) => typeof t === 'string' && t.startsWith('ExponentPushToken'));
  if (!validTokens.length) return;
  const messages = validTokens.map((token) => ({
    to: token,
    sound: 'default',
    title,
    body,
    data,
    priority: 'high',
  }));
  const chunks = chunkArray(messages, 100);
  for (const chunk of chunks) {
    try {
      await axios.post(EXPO_PUSH_URL, chunk, {
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      });
    } catch (err) {
      console.error('Push send failed:', err?.response?.data || err?.message || err);
    }
  }
};

const resolveUserId = async (userIdentifier) => {
  if (!userIdentifier) return null;
  const raw = String(userIdentifier).trim();
  if (!raw) return null;
  let user = null;
  if (raw.includes('@')) {
    user = await User.findOne({ email: raw.toLowerCase() });
  } else {
    user = await User.findOne({ id: raw });
    if (!user) user = await User.findOne({ email: raw.toLowerCase() });
  }
  return user?.id || raw;
};

const getUserPushTokens = async (userIdentifier) => {
  if (!userIdentifier) return [];
  const raw = String(userIdentifier).trim();
  const query = raw.includes('@')
    ? { userEmail: raw.toLowerCase() }
    : { userId: raw };
  let tokens = await NotificationToken.find(query).lean();
  if (!tokens.length && !raw.includes('@')) {
    const user = await User.findOne({ id: raw });
    if (user?.email) {
      tokens = await NotificationToken.find({ userEmail: user.email.toLowerCase() }).lean();
    }
  }
  return tokens.map((t) => t.token).filter(Boolean);
};

const sendPushToUser = async (userId, { title, body, data }) => {
  if (!userId) return;
  const canonical = await resolveUserId(userId);
  const tokens = await getUserPushTokens(canonical || userId);
  await sendPushNotifications(tokens, { title, body, data });
};

const sendPushToAllUsers = async ({ title, body, data }) => {
  const tokens = await NotificationToken.find().lean();
  await sendPushNotifications(tokens.map((t) => t.token), { title, body, data });
};

const ENGAGEMENT_MESSAGES = [
  {
    title: 'Daily Health Tip',
    message: 'Stay hydrated today. Aim for 6–8 glasses of water and avoid sugary drinks.',
  },
  {
    title: 'Wellness Reminder',
    message: 'A 20-minute walk can improve mood and blood sugar control. Try to take one today.',
  },
  {
    title: 'Sleep Check',
    message: 'Try to get 7–8 hours of sleep tonight. Consistent sleep improves immunity and focus.',
  },
  {
    title: 'Nutrition Tip',
    message: 'Include a source of protein and fiber in each meal to stay full and balanced.',
  },
  {
    title: 'Medication Safety',
    message: 'Avoid doubling doses. If you miss a dose, consult your doctor or pharmacist.',
  },
];

const createNotification = async ({ userId, title, message, type = 'general', relatedId = null }) => {
  if (!userId || !title || !message) return null;
  const canonicalUserId = await resolveUserId(userId);
  const notification = new Notification({
    userId: canonicalUserId || userId,
    title,
    message,
    type,
    relatedId: relatedId || null,
    date: new Date(),
  });
  await notification.save();
  return notification;
};

const maybeCreateEngagementNotification = async (userId) => {
  const last = await Notification.findOne({ userId, type: 'engagement' }).sort({ date: -1 });
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  if (last && last.date && last.date > dayAgo) return;
  const pick = ENGAGEMENT_MESSAGES[Math.floor(Math.random() * ENGAGEMENT_MESSAGES.length)];
  await createNotification({
    userId,
    title: pick.title,
    message: pick.message,
    type: 'engagement',
  });
};

// Multer upload routes for chat
app.post('/upload/image', upload1.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: `/Uploads/${req.file.filename}` });
});

app.post('/upload/document', upload1.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: `/Uploads/${req.file.filename}` });
});

app.post('/upload/voice', upload1.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: `/Uploads/${req.file.filename}` });
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('User connected:', socket.id, 'Query:', socket.handshake.query);
  socket.on('join', async (userId) => {
    console.log('User joined chat:', userId, 'Socket ID:', socket.id);
    socket.join(userId);


    try {
      const messages = await ChatMessage.find({
        $or: [{ sender: userId, receiver: 'admin' }, { sender: 'admin', receiver: userId }],
      }).sort({ timestamp: 1 });
      console.log(`Sending ${messages.length} previous messages to user ${userId}`);
      socket.emit('previousMessages', messages);
    } catch (err) {
      console.error('Error fetching previous messages for user', userId, ':', err.message);
    }
  });

  socket.on('sendMessage', async (msg, callback) => {
    console.log('Received sendMessage:', msg);
    try {
      const newMsg = new ChatMessage({
        _id: new mongoose.Types.ObjectId().toString(),
        sender: msg.sender,
        receiver: msg.receiver,
        type: msg.type,
        content: msg.content,
        timestamp: new Date(),
      });
      await newMsg.save();
      console.log('Message saved, emitting to', msg.sender, msg.receiver);
      io.to(msg.receiver).emit('receiveMessage', newMsg);
      io.to(msg.sender).emit('receiveMessage', newMsg);
      if (callback) callback({ success: true });
    } catch (err) {
      console.error('Error saving message:', err.message);
      if (callback) callback({ error: err.message });
    }
  });

  socket.on('disconnect', () => console.log('User disconnected:', socket.id));
});

app.post('/api/chat/send', authMiddleware, async (req, res) => {
  try {
    const { receiver, type, content } = req.body;
    const userId = req.user.id;

    if (!receiver || !type || !content) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newMsg = new ChatMessage({
      _id: new mongoose.Types.ObjectId().toString(),
      sender: userId,
      receiver,
      type,
      content,
      timestamp: new Date(),
    });

    await newMsg.save();
    console.log('POST /api/chat/send: Message saved and emitting');

    io.to(receiver).emit('receiveMessage', newMsg);
    io.to(userId).emit('receiveMessage', newMsg);

    // If sending to admin, no notification needed for admin usually, 
    // but if admin is sending to user, handle it.
    if (userId === 'admin' && receiver !== 'admin') {
      try {
        const notification = new Notification({
          userId: receiver,
          title: 'New Message from Admin',
          message: type === 'text' ? content : `Sent a ${type}`,
          type: 'chat',
          relatedId: newMsg._id,
          date: new Date()
        });
        await notification.save();
        await sendPushToUser(receiver, {
          title: 'New Message from Admin',
          body: type === 'text' ? content : `Sent a ${type}`,
          data: { type: 'chat', chatId: newMsg._id }
        });
      } catch (err) { }
    }

    res.status(200).json({ success: true, message: newMsg });
  } catch (err) {
    console.error('POST /api/chat/send error:', err.message);
    res.status(500).json({ error: 'Failed to send message: ' + err.message });
  }
});

// Chat Routes
app.post('/chat/upload', authMiddleware, uploadChat.single('file'), async (req, res) => {
  try {
    const { userId, type, receiver } = req.body;
    console.log('POST /chat/upload: Received data:', { userId, type, receiver, hasFile: !!req.file });

    if (!userId || !type || !receiver) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Cloudinary URL is in req.file.path
    const messageContent = req.file.path;

    const newMsg = new ChatMessage({
      _id: new mongoose.Types.ObjectId().toString(),
      sender: userId,
      receiver,
      type,
      content: messageContent,
      timestamp: new Date(),
    });

    await newMsg.save();
    console.log('POST /chat/upload: Message saved to Cloudinary and MongoDB:', messageContent);

    io.to(receiver).emit('receiveMessage', newMsg);
    io.to(userId).emit('receiveMessage', newMsg);
    io.to('admin').emit('receiveMessage', newMsg); // Ensure admin dashboard sees it

    // If admin is sending to user, create notification
    if (userId === 'admin' && receiver !== 'admin') {
      try {
        const notification = new Notification({
          userId: receiver,
          title: 'New Message from Admin',
          message: type === 'text' ? req.body.content : `Sent a ${type}`,
          type: 'chat',
          relatedId: newMsg._id,
          date: new Date()
        });
        await notification.save();
        console.log('Notification created for user:', receiver);
        await sendPushToUser(receiver, {
          title: 'New Message from Admin',
          body: type === 'text' ? req.body.content : `Sent a ${type}`,
          data: { type: 'chat', chatId: newMsg._id }
        });
      } catch (notifErr) {
        console.error('Failed to create notification:', notifErr.message);
      }
    }

    res.status(200).json({ message: 'File uploaded and message sent successfully', url: messageContent });
  } catch (err) {
    console.error('POST /chat/upload: Error:', err.message);
    res.status(500).json({ error: 'Failed to upload file: ' + err.message });
  }
});

app.get('/api/debug-auth', (req, res) => {
  res.json({
    secret_length: SECRET_KEY.length,
    secret_prefix: SECRET_KEY.substring(0, 3)
  });
});

app.get('/api/messages/admin', authMiddleware, async (req, res) => {
  try {
    let userId = req.user.id;
    const targetUserId = req.query.userId;

    // If caller is admin and targetUserId is provided, fetch for that user
    if (req.user.role === 'admin' && targetUserId) {
      userId = targetUserId;
    }

    console.log('GET /api/messages/admin: Fetching messages for user:', userId);
    const messages = await ChatMessage.find({
      $or: [
        { sender: userId, receiver: 'admin' },
        { sender: 'admin', receiver: userId },
      ],
    }).sort({ timestamp: 1 });
    console.log(`GET /api/messages/admin: Fetched ${messages.length} messages for user ${userId}`);
    res.json(messages);
  } catch (err) {
    console.error('GET /api/messages/admin: Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch messages: ' + err.message });
  }
});

// ------------------- MediApp AI Chat -------------------
const MEDICAL_KEYWORDS = [
  'symptom', 'symptoms', 'fever', 'pain', 'cough', 'cold', 'flu', 'headache',
  'nausea', 'vomit', 'vomiting', 'diarrhea', 'dizzy', 'dizziness', 'allergy',
  'infection', 'burn', 'injury', 'wound', 'rash', 'skin', 'itch', 'itching',
  'stomach', 'abdomen', 'abdominal', 'blood pressure', 'bp', 'sugar', 'diabetes',
  'asthma', 'heart', 'chest', 'pregnant', 'pregnancy', 'period', 'menstrual',
  'doctor', 'clinic', 'medicine', 'medication', 'tablet', 'capsule', 'syrup',
  'antibiotic', 'dose', 'dosage', 'mg', 'ml', 'ointment', 'cream', 'spray',
  'vitamin', 'supplement', 'prescription', 'otc', 'painkiller', 'analgesic',
  'health', 'healthcare', 'pharmacy',
];

const isMedicalQuery = (text) => {
  const t = (text || '').toLowerCase();
  if (!t.trim()) return false;
  return MEDICAL_KEYWORDS.some((k) => t.includes(k));
};

const normalizeText = (text) => (text || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
const tokenize = (text) => normalizeText(text).split(/\s+/).filter(Boolean);

const GREETING_WORDS = new Set([
  'hi', 'hello', 'hey', 'salam', 'salaam', 'assalam', 'asalam', 'alaikum',
  'aoa', 'hola', 'hi!', 'hello!', 'assalam-o-alaikum',
]);

const isGreetingOnly = (text) => {
  const t = normalizeText(text).trim();
  if (!t) return false;
  const words = t.split(/\s+/).filter(Boolean);
  if (words.length > 4) return false;
  return words.every((w) => GREETING_WORDS.has(w) || w === 'o');
};

const ROMAN_URDU_HINTS = [
  'kya', 'ky', 'kyun', 'kyu', 'kaise', 'kaisay', 'kaisa', 'kab', 'kahan',
  'mujhe', 'mujhay', 'ap', 'aap', 'apko', 'aapko', 'mera', 'meri', 'mere',
  'hum', 'ham', 'dard', 'bukhar', 'khansi', 'zukaam', 'nazla', 'gala', 'sir', 'pet',
  'dawai', 'dawa', 'goli', 'tablet', 'syrup', 'nahi', 'haan', 'theek',
  'madad', 'batao', 'bataiye', 'bata', 'please', 'shukriya',
  'hai', 'hain', 'ho', 'hoga', 'hogi', 'tha', 'thi', 'thay',
  'raha', 'rahi', 'rahay', 'jata', 'jaati', 'jae', 'jay', 'dein', 'de',
  'mat', 'jalan', 'thakan', 'chakkar', 'ultee', 'ulti', 'garmi', 'sardi',
  'saans', 'sanse', 'sansein', 'saansain', 'zakhm',
];

const hasUrduScript = (text) => /[\u0600-\u06FF]/.test(text || '');

const detectLanguage = (text) => {
  const t = (text || '').toLowerCase();
  if (!t.trim()) return 'english';
  if (hasUrduScript(t)) return 'roman_urdu';
  const hasRomanUrdu = ROMAN_URDU_HINTS.some((w) => t.includes(w));
  return hasRomanUrdu ? 'roman_urdu' : 'english';
};

const findRelevantMedicines = (query, medicines, limit = 8) => {
  const qTokens = tokenize(query);
  if (!qTokens.length) return [];
  const qSet = new Set(qTokens);
  const scored = [];
  for (const med of medicines) {
    const fields = [
      med.name,
      med.description,
      med.category,
      med.manufacturer,
      med.dosage,
      med.medicineType,
    ].filter(Boolean).join(' ');
    const fieldsLower = normalizeText(fields);
    const mTokens = tokenize(fields);
    let score = 0;
    for (const t of mTokens) {
      if (qSet.has(t)) score += 1;
    }
    const partialMatch = qTokens.some((t) => fieldsLower.includes(t));
    if ((score > 0 || partialMatch) && Number(med.quantity || 0) > 0) {
      scored.push({ med, score: score + (partialMatch ? 0.5 : 0) });
    }
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((s) => s.med);
};

const SYMPTOM_HINTS = [
  {
    keywords: ['fever', 'temperature', 'bukhar'],
    hints: ['paracetamol', 'acetaminophen', 'panadol', 'calpol', 'ibuprofen', 'brufen'],
  },
  {
    keywords: ['pain', 'dard', 'headache', 'migraine', 'body ache'],
    hints: ['ibuprofen', 'paracetamol', 'diclofenac', 'naproxen', 'brufen'],
  },
  {
    keywords: ['cough', 'khansi', 'sore throat', 'throat'],
    hints: ['dextromethorphan', 'guaifenesin', 'ambroxol', 'bromhexine'],
  },
  {
    keywords: ['allergy', 'rash', 'itch', 'itching', 'hives', 'naazla', 'nazla'],
    hints: ['cetirizine', 'loratadine', 'fexofenadine'],
  },
  {
    keywords: ['cold', 'flu', 'zukam', 'nazla'],
    hints: ['chlorpheniramine', 'phenylephrine', 'paracetamol', 'ibuprofen'],
  },
  {
    keywords: ['diarrhea', 'loose motion', 'dast'],
    hints: ['loperamide', 'ors', 'oral rehydration'],
  },
  {
    keywords: ['acidity', 'gas', 'heartburn', 'stomach', 'ulcer'],
    hints: ['omeprazole', 'pantoprazole', 'antacid', 'ranitidine'],
  },
];

const findSymptomBasedSuggestions = (text, medicines, limit = 6) => {
  const t = (text || '').toLowerCase();
  const hit = SYMPTOM_HINTS.find((h) => h.keywords.some((k) => t.includes(k)));
  if (!hit) return [];
  const result = medicines.filter((m) => {
    if (Number(m.quantity || 0) <= 0) return false;
    const name = (m.name || '').toLowerCase();
    return hit.hints.some((h) => name.includes(h));
  });
  return result.slice(0, limit);
};

const getTopInStock = (medicines, limit = 6) => {
  return (medicines || [])
    .filter((m) => Number(m.quantity || 0) > 0)
    .sort((a, b) => Number(b.quantity || 0) - Number(a.quantity || 0))
    .slice(0, limit);
};

const buildClassificationPrompt = (messages, text) => {
  const recent = (messages || []).slice(-6).map((m) => `${m.role}: ${m.content}`).join('\n');
  return `Conversation so far:\n${recent}\nCurrent question: ${text}\nReply with only "medical" or "non-medical".`;
};

const hasRecentMedicalContext = (messages) => {
  const recent = (messages || []).slice(-6);
  return recent.some((m) => isMedicalQuery(m.content));
};

const isFollowUpQuestion = (text) => {
  const t = (text || '').toLowerCase();
  if (!t.trim()) return false;
  const wordCount = t.split(/\s+/).filter(Boolean).length;
  if (wordCount > 14) return false;
  const pronouns = ['that', 'it', 'this', 'those', 'them', 'ye', 'wo', 'usse', 'is', 'us'];
  const actions = ['prevent', 'avoid', 'manage', 'treat', 'cure', 'recover', 'after', 'again', 'bach', 'bachao', 'bacha', 'rok', 'rokna'];
  const hasPronoun = pronouns.some((p) => t.includes(p));
  const hasAction = actions.some((a) => t.includes(a));
  return hasPronoun || hasAction;
};

const buildSystemPrompt = ({ storeNames, summary, facts, lastSuggested, language }) => {
  const storeText = storeNames.length
    ? `MediApp Store Medicines (prefer these first): ${storeNames.join(', ')}.`
    : 'MediApp Store Medicines list is currently unavailable.';
  const factParts = [];
  if (facts?.age) factParts.push(`Age: ${facts.age}`);
  if (facts?.conditions?.length) factParts.push(`Conditions: ${facts.conditions.join(', ')}`);
  if (facts?.allergies?.length) factParts.push(`Allergies: ${facts.allergies.join(', ')}`);
  if (facts?.medications?.length) factParts.push(`Medications: ${facts.medications.join(', ')}`);
  const factsText = factParts.length ? `Known user facts: ${factParts.join(' | ')}.` : '';
  const summaryText = summary ? `Conversation summary: ${summary}` : '';
  const avoidRepeat = lastSuggested?.length
    ? `Avoid repeating these medicines unless clearly relevant: ${lastSuggested.join(', ')}.`
    : '';
  const languageLine = language === 'roman_urdu'
    ? 'Respond in Roman Urdu. Always keep the same language as the user.'
    : 'Respond in English. Always keep the same language as the user.';
  return [
    'You are MediApp AI, a medical-only assistant acting like a cautious AI doctor.',
    'Use the conversation context and summary to answer follow-up questions. Keep continuity across turns.',
    'Respond only to medical/health-related questions. If non-medical, politely refuse and ask for a medical question.',
    'Do not switch languages. Always reply in the same language as the user.',
    'Avoid unsafe advice and encourage seeing a clinician for serious or persistent symptoms.',
    'If suggesting medicines, first prioritize medicines available in MediApp Store list. If none are relevant, then suggest external/common OTC options.',
    'If the user greets you (hi/hello/salam), respond politely and invite a medical question.',
    'Mention availability inline when you suggest a medicine (e.g., "MediApp Store me available hai" or "available nahi"). Do not put availability only at the end.',
    languageLine,
    'If you mention any store medicines, add a final line exactly in this format: MEDIAPP_STORE: name1, name2.',
    'Use exact store medicine names from the provided list. If none, write: MEDIAPP_STORE: none.',
    summaryText,
    factsText,
    avoidRepeat,
    storeText,
  ].join(' ');
};

const findStoreMatches = (text, medicines) => {
  const t = (text || '').toLowerCase();
  return medicines.filter((m) => (m.name || '').toLowerCase() && t.includes((m.name || '').toLowerCase()) && Number(m.quantity || 0) > 0);
};

const classifyMedicalWithGroq = async (text, groqKey, model, contextMessages = []) => {
  const userContent = contextMessages.length ? buildClassificationPrompt(contextMessages, text) : text;
  const payload = {
    model,
    temperature: 0,
    max_tokens: 5,
    messages: [
      { role: 'system', content: 'You are a classifier. Reply with only "medical" or "non-medical".' },
      { role: 'user', content: userContent },
    ],
  };
  const resp = await axios.post('https://api.groq.com/openai/v1/chat/completions', payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${groqKey}`,
    },
    timeout: 12000,
  });
  const label = (resp?.data?.choices?.[0]?.message?.content || '').trim().toLowerCase();
  return label.includes('non') ? 'non-medical' : 'medical';
};

const summarizeConversationWithGroq = async ({ messages, summary, groqKey, model }) => {
  const recent = (messages || []).slice(-24).map((m) => `${m.role}: ${m.content}`).join('\n');
  const payload = {
    model,
    temperature: 0.2,
    max_tokens: 220,
    messages: [
      {
        role: 'system',
        content: 'Summarize the medical conversation for continuity. Keep it concise (3-6 sentences). Focus on symptoms, timeline, diagnoses, meds, advice, and open questions.',
      },
      {
        role: 'user',
        content: `Existing summary (if any): ${summary || 'none'}\nRecent conversation:\n${recent}`,
      },
    ],
  };
  const resp = await axios.post('https://api.groq.com/openai/v1/chat/completions', payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${groqKey}`,
    },
    timeout: 15000,
  });
  return (resp?.data?.choices?.[0]?.message?.content || '').trim();
};

const extractFactsWithGroq = async ({ messages, summary, groqKey, model }) => {
  const recent = (messages || []).slice(-20).map((m) => `${m.role}: ${m.content}`).join('\n');
  const payload = {
    model,
    temperature: 0,
    max_tokens: 180,
    messages: [
      {
        role: 'system',
        content: 'Extract patient facts from the conversation. Return only JSON with keys: age (string), conditions (array), allergies (array), medications (array). Use empty string/array if unknown.',
      },
      {
        role: 'user',
        content: `Summary: ${summary || 'none'}\nConversation:\n${recent}`,
      },
    ],
  };
  const resp = await axios.post('https://api.groq.com/openai/v1/chat/completions', payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${groqKey}`,
    },
    timeout: 15000,
  });
  const raw = (resp?.data?.choices?.[0]?.message?.content || '').trim();
  try {
    return JSON.parse(raw);
  } catch (err) {
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
      return JSON.parse(match[0]);
    } catch (err2) {
      return null;
    }
  }
};

const mergeFacts = (current, incoming) => {
  if (!incoming) return current;
  const next = {
    age: current?.age || '',
    conditions: Array.isArray(current?.conditions) ? [...current.conditions] : [],
    allergies: Array.isArray(current?.allergies) ? [...current.allergies] : [],
    medications: Array.isArray(current?.medications) ? [...current.medications] : [],
  };
  if (!next.age && incoming.age) next.age = String(incoming.age);
  const addUnique = (arr, items) => {
    const set = new Set(arr.map((v) => String(v).toLowerCase()));
    (items || []).forEach((v) => {
      const val = String(v || '').trim();
      if (!val) return;
      const key = val.toLowerCase();
      if (!set.has(key)) {
        set.add(key);
        arr.push(val);
      }
    });
  };
  addUnique(next.conditions, incoming.conditions);
  addUnique(next.allergies, incoming.allergies);
  addUnique(next.medications, incoming.medications);
  return next;
};

const containsAnySuggestion = (text, suggestions) => {
  if (!text || !Array.isArray(suggestions) || !suggestions.length) return false;
  const t = String(text).toLowerCase();
  return suggestions.some((m) => t.includes(String(m.name || '').toLowerCase()));
};

const insertInlineAfterFirstSentence = (text, inline) => {
  const base = String(text || '').trim();
  if (!base) return inline;
  const match = base.match(/[.!?]/);
  if (match && match.index !== undefined) {
    const idx = match.index + 1;
    const head = base.slice(0, idx).trim();
    const tail = base.slice(idx).trim();
    return tail ? `${head} ${inline} ${tail}` : `${head} ${inline}`;
  }
  return `${base} ${inline}`.trim();
};

const extractStoreSuggestions = (text) => {
  if (!text) return { cleanedContent: '', names: [] };
  const regex = /(?:^|\n)\s*MEDIAPP_STORE\s*:\s*(.+?)(?:\n|$)/i;
  const match = text.match(regex);
  if (!match) return { cleanedContent: text.trim(), names: [] };
  const raw = (match[1] || '').trim();
  const names = raw.toLowerCase() === 'none'
    ? []
    : raw.split(',').map((n) => n.trim()).filter(Boolean);
  const cleanedContent = text.replace(match[0], '').replace(/\n{3,}/g, '\n\n').trim();
  return { cleanedContent, names };
};

const matchStoreNames = (names, medicines) => {
  if (!Array.isArray(names) || !names.length) return [];
  const medMap = new Map();
  const lowerMap = new Map(
    medicines.map((m) => [String(m.name || '').toLowerCase(), m]).filter(([k]) => k)
  );
  for (const name of names) {
    const key = String(name || '').toLowerCase();
    const direct = lowerMap.get(key);
    if (direct && Number(direct.quantity || 0) > 0) {
      medMap.set(String(direct._id), direct);
      continue;
    }
    const partial = medicines.find((m) => String(m.name || '').toLowerCase().includes(key) && Number(m.quantity || 0) > 0);
    if (partial) medMap.set(String(partial._id), partial);
  }
  return Array.from(medMap.values());
};

app.get('/api/ai/chats', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const limit = Math.max(1, Math.min(Number(req.query.limit || 50), 200));
    const sessions = await AIChatSession.find({ userId })
      .sort({ updatedAt: -1 })
      .limit(limit)
      .select({ _id: 1, title: 1, updatedAt: 1, messages: { $slice: -1 } })
      .lean();
    const result = sessions.map((s) => ({
      _id: s._id,
      title: s.title,
      updatedAt: s.updatedAt,
      lastMessage: s.messages?.length ? s.messages[s.messages.length - 1].content : '',
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch AI chats: ' + err.message });
  }
});

app.get('/api/ai/chats/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const session = await AIChatSession.findOne({ _id: req.params.id, userId }).lean();
    if (!session) return res.status(404).json({ error: 'Chat not found' });
    const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 500));
    if (Array.isArray(session.messages) && session.messages.length > limit) {
      session.messages = session.messages.slice(-limit);
    }
    res.json(session);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch AI chat: ' + err.message });
  }
});

app.delete('/api/ai/chats/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const deleted = await AIChatSession.findOneAndDelete({ _id: req.params.id, userId });
    if (!deleted) return res.status(404).json({ error: 'Chat not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete AI chat: ' + err.message });
  }
});

app.delete('/api/ai/chats', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    await AIChatSession.deleteMany({ userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete AI chats: ' + err.message });
  }
});

app.post('/api/ai/respond', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const { sessionId, message } = req.body || {};
    const text = (message || '').trim();
    if (!text) return res.status(400).json({ error: 'Message is required' });

    let session = null;
    if (sessionId) {
      session = await AIChatSession.findOne({ _id: sessionId, userId });
    }

    if (!session) {
      const lastSession = await AIChatSession.findOne({ userId }).sort({ updatedAt: -1 }).lean();
      session = new AIChatSession({
        userId,
        title: text.slice(0, 60),
        facts: lastSession?.facts || undefined,
        messages: [],
      });
    }

    // Store user message
    session.messages.push({ role: 'user', content: text, createdAt: new Date() });

    const incomingKey = req.body?.groqKey || '';
    let groqKey =
      process.env.GROQ_API_KEY ||
      process.env.GROQ_KEY ||
      process.env.GROQ_APIKEY ||
      process.env.GROQ ||
      incomingKey ||
      res.locals.settings?.apiKey ||
      '';
    if (incomingKey && !res.locals.settings?.apiKey) {
      try {
        let settings = await Settings.findOne();
        if (!settings) settings = new Settings();
        if (!settings.apiKey) {
          settings.apiKey = incomingKey;
          await settings.save();
          res.locals.settings.apiKey = incomingKey;
        }
      } catch (err) {
        console.error('Failed to persist Groq key:', err.message);
      }
      groqKey = groqKey || incomingKey;
    }

    if (isGreetingOnly(text)) {
      const greeting = 'Assalam-o-Alaikum! Main MediApp AI hoon. Apni medical ya health concern batayein, main madad karunga.';
      session.messages.push({ role: 'assistant', content: greeting, createdAt: new Date() });
      await session.save();
      return res.json({ sessionId: session._id, response: greeting, suggestions: [] });
    }

    if (!groqKey) {
      try {
        const settings = await Settings.findOne();
        groqKey = settings?.apiKey || '';
      } catch (err) {
        console.error('Failed to load Groq key from settings:', err.message);
      }
    }

    if (!groqKey) {
      await session.save();
      // Fallback to keyword rule if no Groq key
      const hasContext = hasRecentMedicalContext(session.messages) || Boolean(session.summary);
      const allowFollowUp = hasContext && isFollowUpQuestion(text);
      if (!isMedicalQuery(text) && !allowFollowUp) {
        const refusal = 'I can only answer medical and health-related questions. Please ask about symptoms, medicines, dosage, or health concerns.';
        session.messages.push({ role: 'assistant', content: refusal, createdAt: new Date() });
        await session.save();
        return res.json({ sessionId: session._id, response: refusal, suggestions: [] });
      }
      return res.status(503).json({ error: 'GROQ_API_KEY is not configured on the server.', sessionId: session._id });
    }

    const groqModel = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';

    // Classify medical vs non-medical using Groq (avoid keyword-only behavior)
    const classification = await classifyMedicalWithGroq(text, groqKey, groqModel, session.messages);
    const allowFollowUp = (hasRecentMedicalContext(session.messages) || Boolean(session.summary)) && isFollowUpQuestion(text);
    if (classification === 'non-medical' && !allowFollowUp) {
      const refusal = 'I can only answer medical and health-related questions. Please ask about symptoms, medicines, dosage, or health concerns.';
      session.messages.push({ role: 'assistant', content: refusal, createdAt: new Date() });
      await session.save();
      return res.json({ sessionId: session._id, response: refusal, suggestions: [] });
    }

    const medicines = await Medicine.find().select('name price image dosage manufacturer medicineType description category quantity').lean();
    const storeNames = medicines.map((m) => m.name).filter(Boolean).slice(0, 200);
    const systemPrompt = buildSystemPrompt({
      storeNames,
      summary: session.summary,
      facts: session.facts,
      lastSuggested: session.lastSuggested,
      language: detectLanguage(text),
    });

    const payload = {
      model: groqModel,
      temperature: 0.4,
      max_tokens: 512,
      messages: [
        { role: 'system', content: systemPrompt },
        ...session.messages.slice(-40).map((m) => ({ role: m.role, content: m.content })),
      ],
    };

    const groqResp = await axios.post('https://api.groq.com/openai/v1/chat/completions', payload, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${groqKey}`,
      },
      timeout: 20000,
    });

    const content = groqResp?.data?.choices?.[0]?.message?.content || 'No response received.';
    const { cleanedContent, names } = extractStoreSuggestions(content);
    const nameMatches = matchStoreNames(names, medicines);
    const storeMatches = findStoreMatches(cleanedContent, medicines);
    const queryMatches = findRelevantMedicines(text, medicines);
    const symptomMatches = findSymptomBasedSuggestions(text, medicines);
    let merged = [...nameMatches, ...queryMatches, ...symptomMatches, ...storeMatches];
    const uniqueById = new Map();
    for (const m of merged) {
      if (m && m._id) uniqueById.set(String(m._id), m);
    }
    let suggestions = Array.from(uniqueById.values()).slice(0, 8);
    if (session.lastSuggested?.length && suggestions.length) {
      const lastSet = new Set(session.lastSuggested.map((n) => String(n).toLowerCase()));
      const filtered = suggestions.filter((m) => !lastSet.has(String(m.name || '').toLowerCase()));
      if (filtered.length) suggestions = filtered;
    }

    let finalContent = cleanedContent;
    if (suggestions.length && !containsAnySuggestion(finalContent, suggestions)) {
      const inlineNames = suggestions.map((m) => m.name).filter(Boolean).slice(0, 4);
      if (inlineNames.length) {
        const inline = `Recommended (MediApp Store, available): ${inlineNames.join(', ')}.`;
        finalContent = insertInlineAfterFirstSentence(finalContent, inline);
      }
    }

    session.messages.push({ role: 'assistant', content: finalContent, createdAt: new Date() });

    const messageCount = session.messages.length;
    if (messageCount - (session.summaryMessageCount || 0) >= 10) {
      const newSummary = await summarizeConversationWithGroq({
        messages: session.messages,
        summary: session.summary,
        groqKey,
        model: groqModel,
      });
      if (newSummary) {
        session.summary = newSummary;
        session.summaryMessageCount = messageCount;
      }
      const extracted = await extractFactsWithGroq({
        messages: session.messages,
        summary: session.summary,
        groqKey,
        model: groqModel,
      });
      session.facts = mergeFacts(session.facts, extracted);
    }

    session.lastSuggested = suggestions.map((m) => m.name).filter(Boolean).slice(0, 10);
    await session.save();

    res.json({
      sessionId: session._id,
      response: finalContent,
      suggestions: suggestions.map((m) => ({
        _id: m._id,
        name: m.name,
        price: m.price,
        image: m.image,
        dosage: m.dosage,
        manufacturer: m.manufacturer,
        medicineType: m.medicineType,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: 'AI response failed: ' + err.message });
  }
});

app.post('/api/ai/append', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const { sessionId, role, content } = req.body || {};
    if (!sessionId || !role || !content) {
      return res.status(400).json({ error: 'sessionId, role, and content are required' });
    }
    if (!['user', 'assistant'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const session = await AIChatSession.findOne({ _id: sessionId, userId });
    if (!session) return res.status(404).json({ error: 'Chat not found' });
    session.messages.push({ role, content, createdAt: new Date() });
    await session.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to append message: ' + err.message });
  }
});

// ------------------- Notifications API -------------------
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const userEmail = req.user.email?.toLowerCase();
    await maybeCreateEngagementNotification(userId);
    const notifications = await Notification.find({
      userId: { $in: [userId, userEmail].filter(Boolean) },
    })
      .sort({ date: -1 })
      .limit(100)
      .lean();
    res.json(notifications);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch notifications: ' + err.message });
  }
});

app.put('/api/notifications/read', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const userEmail = req.user.email?.toLowerCase();
    await Notification.updateMany(
      { userId: { $in: [userId, userEmail].filter(Boolean) }, read: false },
      { $set: { read: true } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to mark notifications as read: ' + err.message });
  }
});

app.post('/api/notifications/register', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.email;
    const userEmail = req.user.email?.toLowerCase() || '';
    const { token, platform } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Token is required' });
    await NotificationToken.findOneAndUpdate(
      { token },
      { userId, userEmail, platform: platform || 'android', updatedAt: new Date() },
      { upsert: true, new: true }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to register token: ' + err.message });
  }
});

app.get('/admin/chat', authAdminPage, async (req, res) => {
  try {
    const users = await User.find({ role: 'user' }).select('id firstName lastName email profileImage');
    const selectedUserId = req.query.userId || null;
    let messages = [];
    if (selectedUserId) {
      messages = await ChatMessage.find({
        $or: [
          { sender: selectedUserId, receiver: 'admin' },
          { sender: 'admin', receiver: selectedUserId },
        ],
      }).sort({ timestamp: 1 });
      console.log(`Fetched ${messages.length} messages for user ${selectedUserId}`);
    }
    res.render('chat', {
      user: req.user || {},
      token: req.query.token || '',
      users: users || [],
      messages: messages || [],
      selectedUserId,
      currentPath: '/admin/chat',
      message: req.query.message || null,
      error: req.query.error || null,
      settings: res.locals.settings || { darkMode: false },
    });
  } catch (err) {
    console.error('Error fetching chat data:', err);
    res.render('chat', {
      user: req.user || {},
      token: req.query.token || '',
      users: [],
      messages: [],
      selectedUserId: null,
      currentPath: '/admin/chat',
      message: null,
      error: 'Failed to load chat data: ' + err.message,
      settings: { darkMode: false },
    });
  }
});

app.post('/admin/chat/send', authAdminPage, uploadChat.single('file'), async (req, res) => {
  try {
    const { userId, type, content, caption } = req.body;
    console.log('POST /admin/chat/send: Received data:', { userId, type, content, hasFile: !!req.file });

    if (!userId) {
      return res.status(400).json({ error: 'Missing userId' });
    }

    let messageContent = content;
    if (req.file) {
      messageContent = req.file.path; // Cloudinary URL
    }

    if (!messageContent && type === 'text') {
      return res.status(400).json({ error: 'Text message cannot be empty' });
    }

    const newMsg = new ChatMessage({
      _id: new mongoose.Types.ObjectId().toString(),
      sender: 'admin',
      receiver: userId,
      type,
      content: messageContent,
      caption: caption || '',
      timestamp: new Date(),
    });

    await newMsg.save();
    console.log('POST /admin/chat/send: Message saved to Cloudinary and MongoDB:', newMsg._id);

    io.to(userId).emit('receiveMessage', newMsg);
    io.to('admin').emit('receiveMessage', newMsg); // Explicitly emit to admin room

    // Create notification for user
    try {
      const notification = new Notification({
        userId,
        title: 'New Message from Admin',
        message: type === 'text' ? messageContent : `Sent a ${type}`,
        type: 'chat',
        relatedId: newMsg._id,
        date: new Date()
      });
      await notification.save();
      console.log('Notification created for user:', userId);
      await sendPushToUser(userId, {
        title: 'New Message from Admin',
        body: type === 'text' ? messageContent : `Sent a ${type}`,
        data: { type: 'chat', chatId: newMsg._id }
      });
    } catch (notifErr) {
      console.error('Failed to create notification:', notifErr.message);
    }

    res.status(200).json({ success: true, message: newMsg });
  } catch (err) {
    console.error('POST /admin/chat/send: Error:', err.message);
    res.status(500).json({ error: 'Failed to send message: ' + err.message });
  }
});



// Modified authAdminPage middleware with better logging






// Feedback Schema
const FeedbackSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  userName: { type: String, required: true },
  userProfileImage: { type: String, default: '' }, // Store profile image URL
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, required: true },
  createdAt: { type: Date, default: getPKTDate },
});
const Feedback = mongoose.models.Feedback || mongoose.model('Feedback', FeedbackSchema);

// (Duplicate authMiddleware removed. The original definition above remains in use.)

// Feedback Routes
app.post('/api/feedback', authMiddleware, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    if (!rating || !comment || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating (1-5) and comment are required' });
    }
    const userName = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim() || req.user.email.split('@')[0];
    const feedback = new Feedback({
      userId: req.user.id,
      userName,
      userProfileImage: req.user.profileImage || '',
      rating,
      comment,
      createdAt: new Date(),
    });
    await feedback.save();
    console.log('Feedback submitted:', {
      userId: req.user.id,
      userName,
      userProfileImage: req.user.profileImage,
      rating,
      comment
    });
    res.status(201).json({ message: 'Feedback submitted successfully', feedback });
  } catch (err) {
    console.error('Error submitting feedback:', err);
    res.status(500).json({ error: 'Failed to submit feedback', details: err.message });
  }
});

app.get('/api/feedback', authMiddleware, async (req, res) => {
  try {
    const feedbackList = await Feedback.find().sort({ createdAt: -1 });
    console.log('Feedback fetched for user:', req.user.id, 'Count:', feedbackList.length);
    res.json(feedbackList);
  } catch (err) {
    console.error('Error fetching feedback:', err);
    res.status(500).json({ error: 'Failed to fetch feedback', details: err.message });
  }
});

app.get('/admin/feedback', authAdminPage, async (req, res) => {
  try {
    const expiryThresholdDate = new Date();
    expiryThresholdDate.setDate(expiryThresholdDate.getDate() + res.locals.settings.expiryAlertDays);
    const expiryMedicines = await Medicine.find({ expiryDate: { $lte: expiryThresholdDate, $gte: new Date() } });
    const lowStockMedicines = await Medicine.find({ quantity: { $lte: res.locals.settings.lowStockThreshold } });
    const pendingOrders = await Order.find({ status: 'pending' });
    const feedbackList = await Feedback.find().sort({ createdAt: -1 });
    console.log('Feedback fetched for admin:', req.user.id, 'Count:', feedbackList.length);
    res.render('userfeedback', {
      token: req.query.token || '',
      user: req.user,
      settings: res.locals.settings || { darkMode: false },
      currentPath: '/admin/feedback',
      feedbackList,
      expiryMedicines,
      lowStockMedicines,
      pendingOrders,
      message: req.query.message || null,
      error: req.query.error || null,
    });
  } catch (err) {
    console.error('Error fetching feedback for admin:', err);
    res.render('userfeedback', {
      token: req.query.token || '',
      user: req.user,
      settings: res.locals.settings || { darkMode: false },
      currentPath: '/admin/feedback',
      feedbackList: [],
      expiryMedicines: [],
      lowStockMedicines: [],
      pendingOrders: [],
      message: null,
      error: 'Failed to load feedback: ' + err.message,
    });
  }
});

// Ensure other routes (e.g., /api/auth/login, /api/cart) and app.listen are defined elsewhere

app.get('/admin/add-category', authAdminPage, (req, res) => {
  res.render('add-category', { message: req.query.message || null, error: req.query.error || null, user: req.user, token: req.query.token, currentPath: '/admin/add-category' });
});

app.post('/admin/add-category', authAdminPage, async (req, res) => {
  try {
    let { categoryName } = req.body;
    categoryName = categoryName.trim();
    if (!categoryName) return res.redirect('/admin/add-category?error=Category name is required&token=' + req.query.token);
    let existingCategory = await Category.findOne({ name: categoryName });
    if (existingCategory) return res.redirect('/admin/add-category?error=Category already exists&token=' + req.query.token);
    const newCat = new Category({ name: categoryName });
    await newCat.save();
    res.redirect('/admin/add-category?message=Category added successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/add-category?error=Failed to add category&token=' + req.query.token);
  }
});

app.get('/admin/purchase-history', authAdminPage, async (req, res) => {
  try {
    const onlineOrders = await Order.find().sort({ date: -1 });
    const inPersonSales = await InPersonSale.find()
      .sort({ saleDate: -1 })
      .populate('medicineId', 'name price medicineType dosesPerUnit')
      .populate('adminId', 'firstName lastName profileImage');

    const formattedOnlineOrders = onlineOrders
      .map((order) => {
        const orderTotal = order.cartItems.reduce((sum, item) => sum + (item.price || 0) * (item.cartQuantity || 0), 0);
        return {
          _id: order._id,
          shippingEmail: order.shippingEmail || 'N/A',
          shippingAddress: order.shippingAddress || { firstName: 'Unknown', lastName: '', streetAddress: 'N/A', phoneNumber: 'N/A' },
          orderTotal: orderTotal || order.orderTotal || 0,
          paymentMethod: order.paymentMethod || 'N/A',
          paymentStatus: order.paymentStatus || 'unpaid',
          status: order.status || 'pending',
          date: order.date,
          cartItems: order.cartItems || [],
          statusUpdateHistory: order.statusUpdateHistory || [],
          transactionId: order.transactionId || '',
          shippingFee: order.shippingFee || 0,
        };
      })
      .filter((order) => order.orderTotal > 0);

    const filteredInPersonSales = inPersonSales.filter(
      (sale) =>
        sale.medicineId &&
        typeof sale.medicineId.price === 'number' &&
        typeof sale.quantitySold === 'number' &&
        typeof sale.totalAmount === 'number' &&
        sale.quantitySold > 0
    );

    const now = new Date();
    const calculatePeriodTotals = (period) => {
      const filterDate = (item) => {
        const date = item.date ? new Date(item.date) : new Date(item.saleDate);
        if (period === 'daily') {
          return date.toDateString() === now.toDateString();
        } else if (period === 'weekly') {
          const oneWeekAgo = new Date(now);
          oneWeekAgo.setDate(now.getDate() - 7);
          return date >= oneWeekAgo && date <= now;
        } else if (period === 'fortnightly') {
          const fifteenDaysAgo = new Date(now);
          fifteenDaysAgo.setDate(now.getDate() - 15);
          return date >= fifteenDaysAgo && date <= now;
        } else if (period === 'monthly') {
          return date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
        } else if (period === 'yearly') {
          return date.getFullYear() === now.getFullYear();
        }
        return false;
      };

      const filteredOrders = formattedOnlineOrders.filter(filterDate);
      const filteredSales = filteredInPersonSales.filter(filterDate);
      const totalSales = filteredOrders.reduce((sum, order) => sum + (order.orderTotal || 0), 0) + filteredSales.reduce((sum, sale) => sum + (sale.totalAmount || 0), 0);
      const totalProfit = totalSales * 0.3;
      const totalOrders = filteredOrders.length + filteredSales.length;
      return { totalSales, totalProfit, totalOrders };
    };

    const dailyTotals = calculatePeriodTotals('daily');
    const weeklyTotals = calculatePeriodTotals('weekly');
    const fortnightlyTotals = calculatePeriodTotals('fortnightly');
    const monthlyTotals = calculatePeriodTotals('monthly');
    const yearlyTotals = calculatePeriodTotals('yearly');

    const totalSales = formattedOnlineOrders.reduce((sum, order) => sum + (order.orderTotal || 0), 0) + filteredInPersonSales.reduce((sum, sale) => sum + (sale.totalAmount || 0), 0);
    const totalProfit = totalSales * 0.3;

    const getStatusBadgeClass = function (status) {
      switch (status) {
        case 'Success':
          return 'badge-success';
        case 'Pending':
          return 'badge-warning';
        case 'Cancelled':
          return 'badge-danger';
        case 'Processing':
          return 'badge-info';
        case 'accepted':
          return 'badge-success';
        case 'rejected':
          return 'badge-danger';
        default:
          return 'badge-secondary';
      }
    };

    res.render('purchase-history', {
      onlineOrders: formattedOnlineOrders,
      inPersonSales: filteredInPersonSales,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/purchase-history',
      message: req.query.message || null,
      error: req.query.error || null,
      getStatusBadgeClass,
      dailyTotals: { sales: dailyTotals.totalSales.toFixed(2), profit: dailyTotals.totalProfit.toFixed(2), orders: dailyTotals.totalOrders },
      weeklyTotals: { sales: weeklyTotals.totalSales.toFixed(2), profit: weeklyTotals.totalProfit.toFixed(2), orders: weeklyTotals.totalOrders },
      fortnightlyTotals: { sales: fortnightlyTotals.totalSales.toFixed(2), profit: fortnightlyTotals.totalProfit.toFixed(2), orders: fortnightlyTotals.totalOrders },
      monthlyTotals: { sales: monthlyTotals.totalSales.toFixed(2), profit: monthlyTotals.totalProfit.toFixed(2), orders: monthlyTotals.totalOrders },
      yearlyTotals: { sales: yearlyTotals.totalSales.toFixed(2), profit: yearlyTotals.totalProfit.toFixed(2), orders: yearlyTotals.totalOrders },
      totalSales: totalSales.toFixed(2),
      totalProfit: totalProfit.toFixed(2),
    });
  } catch (err) {
    console.error('Error fetching purchase history:', err);
    res.render('purchase-history', {
      onlineOrders: [],
      inPersonSales: [],
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/purchase-history',
      message: null,
      error: 'Server error: Unable to fetch purchase history',
      getStatusBadgeClass: function (status) {
        switch (status) {
          case 'Success':
            return 'badge-success';
          case 'Pending':
            return 'badge-warning';
          case 'Cancelled':
            return 'badge-danger';
          case 'Processing':
            return 'badge-info';
          case 'accepted':
            return 'badge-success';
          case 'rejected':
            return 'badge-danger';
          default:
            return 'badge-secondary';
        }
      },
      dailyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      weeklyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      fortnightlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      monthlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      yearlyTotals: { sales: '0.00', profit: '0.00', orders: 0 },
      totalSales: '0.00',
      totalProfit: '0.00',
    });
  }
});

app.get('/admin/inperson-sales', authAdminPage, async (req, res) => {
  try {
    const medicines = await Medicine.find().sort({ name: 1 });
    const categories = await Category.find();
    res.render('inperson-sales', {
      medicines,
      categories,
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/inperson-sales',
      message: req.query.message || null,
      error: req.query.error || null,
    });
  } catch (err) {
    console.error(err);
    res.render('inperson-sales', {
      medicines: [],
      categories: [],
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/inperson-sales',
      message: null,
      error: 'Server error',
    });
  }
});

app.post('/admin/inperson-sales', authAdminPage, async (req, res) => {
  try {
    const { medicineId, quantity, customerName, customerContact } = req.body;
    const adminId = req.user.id;

    if (!medicineId || !quantity) return res.redirect(`/admin/inperson-sales?error=Required fields missing&token=${req.query.token}`);

    const medicine = await Medicine.findById(medicineId);
    if (!medicine) return res.redirect(`/admin/inperson-sales?error=Medicine not found&token=${req.query.token}`);

    const quantityNum = parseInt(quantity);
    if (isNaN(quantityNum) || quantityNum <= 0) return res.redirect(`/admin/inperson-sales?error=Invalid quantity&token=${req.query.token}`);

    if (medicine.quantity < quantityNum) return res.redirect(`/admin/inperson-sales?error=Not enough stock. Available: ${medicine.quantity}&token=${req.query.token}`);

    if (!medicine.medicineType) {
      console.warn(`Medicine ${medicine.name} (id: ${medicineId}) missing medicineType, setting default to 'Tablet'`);
      medicine.medicineType = 'Tablet';
    }

    medicine.quantity -= quantityNum;
    await medicine.save();

    const totalAmount = medicine.price * quantityNum;
    const newSale = new InPersonSale({
      medicineId: medicine._id,
      medicineName: medicine.name,
      quantitySold: quantityNum,
      unitType: 'Full',
      customerName,
      customerContact,
      adminId,
      totalAmount,
    });
    await newSale.save();

    res.redirect(`/admin/inperson-sales?message=Sale recorded successfully&token=${req.query.token}`);
  } catch (err) {
    console.error(err);
    res.redirect(`/admin/inperson-sales?error=Server error: ${err.message}&token=${req.query.token}`);
  }
});

app.post('/admin/inperson-sales-record', authAdminPage, async (req, res) => {
  try {
    const { items } = req.body;
    if (!Array.isArray(items) || !items.length) {
      console.warn('Invalid or empty items array:', items);
      return res.status(400).json({ success: false, error: 'Invalid items format', details: 'Items must be a non-empty array' });
    }

    const sales = items.map((item) => ({
      medicineId: item.medicineId,
      medicineName: item.medicineName,
      quantitySold: item.quantitySold,
      unitType: item.unitType,
      customerName: item.customerName || 'In-Person Customer',
      customerContact: item.customerContact || 'N/A',
      adminId: item.adminId,
      totalAmount: item.totalAmount,
    }));

    await InPersonSale.insertMany(sales);
    res.json({ success: true, message: 'Sales recorded successfully' });
  } catch (err) {
    console.error('Error recording sales:', err);
    res.status(500).json({ success: false, error: 'Failed to record sales', details: err.message });
  }
});

app.get('/admin/sales-history', authAdminPage, async (req, res) => {
  try {
    const sales = await InPersonSale.find().sort({ saleDate: -1 }).populate('medicineId');
    res.render('sales-history', { sales, user: req.user, token: req.query.token, message: req.query.message || null, error: req.query.error || null, currentPath: '/admin/sales-history' });
  } catch (err) {
    console.error(err);
    res.render('sales-history', {
      sales: [],
      user: req.user,
      token: req.query.token,
      message: null,
      error: 'Server error',
      currentPath: '/admin/sales-history',
    });
  }
});

// ------------------- Medicine Reminder Schema -------------------
const medicineReminderSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  medicineId: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine', required: false },
  medicineName: { type: String, required: true },
  dosage: { type: String, required: true },
  time: { type: String, required: true }, // e.g., "08:00 AM"
  date: { type: Date, required: true },
  repeat: { type: String, enum: ['None', 'Once', 'Daily', 'Weekly', 'Monthly', 'Custom'], default: 'None' },
  notes: { type: String, default: '' },
  expiryDate: { type: Date },
  createdAt: { type: Date, default: getPKTDate }
});
const MedicineReminder = mongoose.models.MedicineReminder || mongoose.model('MedicineReminder', medicineReminderSchema);

// ------------------- Medicine Reminder Routes -------------------

// Fetch all medicines for dropdown
app.get('/api/medicines/list', authMiddleware, async (req, res) => {
  try {
    const medicines = await Medicine.find().select('name dosage');
    res.json(medicines);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch medicines' });
  }
});

// Create reminder
app.post('/api/reminders', authMiddleware, async (req, res) => {
  try {
    const { medicineId, medicineName, dosage, time, date, repeat, notes, customDays } = req.body;
    if ((!medicineId && !medicineName) || !dosage || !time || !date) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    let medName = medicineName;
    if (medicineId) {
      const medicine = await Medicine.findById(medicineId);
      if (!medicine) return res.status(404).json({ error: 'Medicine not found' });
      medName = medicine.name;
    }

    // Calculate Expiry Date
    const expiryDate = new Date(date);
    const triggerTimeParts = time.match(/(\d+):(\d+)\s*(AM|PM)/i);
    if (triggerTimeParts) {
      let hours = parseInt(triggerTimeParts[1]);
      const minutes = parseInt(triggerTimeParts[2]);
      const ampm = triggerTimeParts[3].toUpperCase();
      if (ampm === 'PM' && hours < 12) hours += 12;
      if (ampm === 'AM' && hours === 12) hours = 0;
      expiryDate.setHours(hours, minutes, 0, 0);
    }

    if (repeat === 'Once' || repeat === 'None') {
      // For one-time, it expires 1 minute after the time
      expiryDate.setMinutes(expiryDate.getMinutes() + 1);
    } else if (repeat === 'Daily') {
      expiryDate.setFullYear(expiryDate.getFullYear() + 10);
    } else if (repeat === 'Weekly') {
      expiryDate.setDate(expiryDate.getDate() + 7);
    } else if (repeat === 'Monthly') {
      expiryDate.setMonth(expiryDate.getMonth() + 1);
    } else if (repeat === 'Custom' && customDays) {
      expiryDate.setDate(expiryDate.getDate() + parseInt(customDays));
    }

    const reminder = new MedicineReminder({
      userId: req.user.id,
      medicineId: medicineId || null,
      medicineName: medName,
      dosage,
      time,
      date,
      repeat,
      notes,
      expiryDate
    });
    await reminder.save();
    res.status(201).json({ message: 'Reminder created successfully', reminder });
  } catch (err) {
    console.error('Reminder Creation Error:', err);
    res.status(500).json({ error: 'Failed to create reminder', details: err.message });
  }
});


// Get reminders for logged-in user
app.get('/api/reminders', authMiddleware, async (req, res) => {
  try {
    const now = getPKTDate();
    const reminders = await MedicineReminder.find({
      userId: req.user.id,
      $or: [
        { expiryDate: { $gt: now } },
        { expiryDate: { $exists: false } }
      ]
    }).sort({ date: 1 });
    res.json(reminders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch reminders' });
  }
});

// Delete reminder
app.delete('/api/reminders/:id', authMiddleware, async (req, res) => {
  try {
    const deleted = await MedicineReminder.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!deleted) return res.status(404).json({ error: 'Reminder not found' });
    res.json({ message: 'Reminder deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete reminder' });
  }
});


// Settings Routes
app.get('/admin/settings', authAdminPage, (req, res) => {
  res.render('settings', {
    user: req.user,
    token: req.query.token,
    currentPath: '/admin/settings',
    message: req.query.message || null,
    error: req.query.error || null,
  });
});

// Admin Notifications (broadcast)
app.get('/admin/notifications', authAdminPage, async (req, res) => {
  try {
    const notifications = await Notification.find().sort({ date: -1 }).limit(50).lean();
    res.render('notifications', {
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/notifications',
      notifications: notifications || [],
      message: req.query.message || null,
      error: req.query.error || null,
    });
  } catch (err) {
    res.render('notifications', {
      user: req.user,
      token: req.query.token,
      currentPath: '/admin/notifications',
      notifications: [],
      message: null,
      error: 'Failed to load notifications: ' + err.message,
    });
  }
});

app.get('/admin/promotions', authAdminPage, async (req, res) => {
  let templates = [];
  let users = [];
  let error = null;
  try {
    templates = PROMO_TEMPLATES.map((t, idx) => ({
      id: idx,
      subject: t.subject,
      headline: t.headline,
      body: t.body,
      cta: t.cta,
    }));
    users = await User.find({
      role: 'user',
      promoOptIn: { $ne: false },
      email: { $exists: true, $ne: '' },
    }).select('id firstName lastName email').lean();
    if (!promoEmailEnabled) {
      error = 'Email not configured (EMAIL_USER / EMAIL_PASS missing).';
    }
  } catch (err) {
    error = err?.response?.data?.message || err.message || 'Failed to load promotions data';
  }
  res.render('promotions', {
    user: req.user,
    token: req.query.token,
    currentPath: '/admin/promotions',
    templates,
    users,
    error,
    message: req.query.message || null,
  });
});

app.post('/admin/promotions/send', authAdminPage, async (req, res) => {
  try {
    if (!promoEmailEnabled || !promoTransporter) {
      return res.status(500).json({ error: 'Email not configured (EMAIL_USER / EMAIL_PASS missing).' });
    }

    const { mode, emails, templateId } = req.body || {};
    const template = PROMO_TEMPLATES[Number(templateId) || 0] || PROMO_TEMPLATES[0];
    const now = new Date();

    let targetUsers = [];
    if (mode === 'selected') {
      const list = Array.isArray(emails) ? emails : [];
      const normalized = list.map((e) => String(e || '').toLowerCase().trim()).filter(Boolean);
      targetUsers = await User.find({ email: { $in: normalized }, role: 'user' }).select('email firstName promoOptIn');
    } else {
      targetUsers = await User.find({
        role: 'user',
        promoOptIn: { $ne: false },
      }).select('email firstName promoOptIn');
    }

    let sent = 0;
    let failed = 0;
    for (const user of targetUsers) {
      if (!user?.email) continue;
      if (user.promoOptIn === false) continue;
      const { subject, text, html } = buildPromoEmail(user, template);
      try {
        await promoTransporter.sendMail({
          from: `"MediApp" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject,
          text,
          html,
        });
        user.promoLastSentAt = now;
        user.promoNextAt = getNextPromoDate(now);
        await user.save();
        sent += 1;
      } catch (mailErr) {
        failed += 1;
        console.error('Promo email failed for', user.email, mailErr.message);
      }
    }

    res.json({ success: true, data: { sent, failed, total: targetUsers.length } });
  } catch (err) {
    res.status(500).json({ error: err?.response?.data?.message || err.message || 'Failed to trigger promotions' });
  }
});

app.post('/api/promotions/run', async (req, res) => {
  try {
    if (!isPromoAuthorized(req)) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!promoEmailEnabled || !promoTransporter) {
      return res.status(500).json({ message: 'Email not configured' });
    }

    const now = new Date();
    const dueUsers = await User.find({
      role: 'user',
      promoOptIn: { $ne: false },
      $or: [{ promoNextAt: { $exists: false } }, { promoNextAt: { $lte: now } }],
    }).select('email firstName promoNextAt promoLastSentAt');

    let sent = 0;
    let failed = 0;
    for (const user of dueUsers) {
      if (!user?.email) continue;
      const template = PROMO_TEMPLATES[Math.floor(Math.random() * PROMO_TEMPLATES.length)];
      const { subject, text, html } = buildPromoEmail(user, template);
      try {
        await promoTransporter.sendMail({
          from: `"MediApp" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject,
          text,
          html,
        });
        user.promoLastSentAt = now;
        user.promoNextAt = getNextPromoDate(now);
        await user.save();
        sent += 1;
      } catch (mailErr) {
        failed += 1;
        console.error('Promo email failed for', user.email, mailErr.message);
      }
    }

    res.json({ message: 'Promotions processed', sent, failed, total: dueUsers.length });
  } catch (err) {
    console.error('Promotions run failed:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/admin/notifications/send', authAdminPage, async (req, res) => {
  try {
    const { title, message } = req.body;
    if (!title || !message) {
      return res.redirect('/admin/notifications?error=Title and message are required&token=' + req.query.token);
    }
    const users = await User.find({ role: 'user' }).select('id').lean();
    const now = new Date();
    const docs = users.map((u) => ({
      userId: u.id,
      title,
      message,
      type: 'broadcast',
      relatedId: null,
      date: now,
      read: false,
    }));
    if (docs.length) {
      await Notification.insertMany(docs);
    }
    await sendPushToAllUsers({
      title,
      body: message,
      data: { type: 'broadcast' },
    });
    res.redirect('/admin/notifications?message=Notification sent to all users&token=' + req.query.token);
  } catch (err) {
    res.redirect('/admin/notifications?error=Failed to send notification&token=' + req.query.token);
  }
});

app.post('/admin/settings', authAdminPage, async (req, res) => {
  try {
    const { lowStockThreshold, expiryAlertDays, emailNotifications, inAppNotifications, defaultUserRole, currency, dateFormat, apiKey, darkMode } = req.body;

    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
    }

    settings.lowStockThreshold = parseInt(lowStockThreshold, 10) || 10;
    settings.expiryAlertDays = parseInt(expiryAlertDays, 10) || 30;
    settings.emailNotifications = emailNotifications === 'on';
    settings.inAppNotifications = inAppNotifications === 'on';
    settings.defaultUserRole = defaultUserRole || 'user';
    settings.currency = currency || 'PKR';
    settings.dateFormat = dateFormat || 'DD/MM/YYYY';
    settings.apiKey = apiKey || '';
    settings.darkMode = darkMode === 'on';

    await settings.save();

    res.redirect('/admin/settings?message=Settings updated successfully&token=' + req.query.token);
  } catch (err) {
    console.error(err);
    res.redirect('/admin/settings?error=Failed to update settings&token=' + req.query.token);
  }
});

app.get('/admin/backup', authAdminPage, async (req, res) => {
  try {
    const backupData = {
      users: await User.find().lean(),
      medicines: await Medicine.find().lean(),
      orders: await Order.find().lean(),
      carts: await Cart.find().lean(),
      inPersonSales: await InPersonSale.find().lean(),
      transactions: await Transaction.find().lean(),
      categories: await Category.find().lean(),
      settings: await Settings.find().lean(),
    };
    const backupDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir);
    const backupFile = path.join(backupDir, `backup-${Date.now()}.json`);
    fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2));
    res.download(backupFile);
  } catch (err) {
    console.error(err);
    res.status(500).send('Backup failed');
  }
});

app.get('/', (req, res) => res.send('Welcome to MediApp'));

// Transaction Routes
app.post('/api/transactions', async (req, res) => {
  try {
    const { userId, walletNumber, walletName, transactionID, depositAmount, orderData } = req.body;
    if (!userId || !walletNumber || !walletName || !transactionID || !depositAmount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newTransaction = new Transaction({
      userId,
      walletNumber,
      walletName,
      transactionID,
      depositAmount: parseFloat(depositAmount),
      orderId: orderData?._id || orderData?.id || null,
    });

    const savedTransaction = await newTransaction.save();

    // If orderId is provided, link it back to the order
    if (newTransaction.orderId) {
      await Order.findByIdAndUpdate(newTransaction.orderId, { transactionId: savedTransaction._id });
    }

    res.status(201).json(savedTransaction);
  } catch (error) {
    console.error('Error creating transaction:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/transactions', async (req, res) => {
  try {
    let filter = {};
    if (req.query.userId) {
      filter.userId = req.query.userId;
    }
    // Only filter by status if explicitly provided
    if (req.query.status) {
      filter.status = req.query.status;
    }
    // If no status filter provided, return all transactions for the user
    const transactions = await Transaction.find(filter).sort({ createdAt: -1 });
    res.json(transactions);
  } catch (error) {
    console.error('Error retrieving transactions:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/transactions/:id', async (req, res) => {
  try {
    const { status } = req.body;
    if (!['Accepted', 'Rejected', 'Pending'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const previousStatus = transaction.status;
    transaction.status = status;
    const updatedTransaction = await transaction.save();

    console.log(`[API] Transaction ${req.params.id} updated to ${status}. Previous status: ${previousStatus}`);

    // If transaction is Accepted and was NOT already Accepted, update order and stock
    if (status === 'Accepted' && previousStatus !== 'Accepted') {
      // Find order by ID or find the latest pending order for this user if orderId is missing
      let order = null;
      if (transaction.orderId) {
        order = await Order.findById(transaction.orderId);
      } else {
        console.log(`[API] Transaction missing orderId, searching latest pending order for ${transaction.userId}`);
        order = await Order.findOne({ userId: transaction.userId, status: 'pending' }).sort({ date: -1 });
      }

        if (order) {
          console.log(`[API] Updating order ${order._id} to accepted and paid.`);
          order.status = 'accepted';
          order.paymentStatus = 'paid';
          order.statusUpdateHistory = order.statusUpdateHistory || [];
          order.statusUpdateHistory.push({ status: 'accepted', timestamp: getPKTDate() });

          // Deduct inventory only if not already reserved
          const affectedIds = [];
          if (!order.stockReserved) {
            for (let item of order.cartItems) {
              const medicineValue = item._id || item.id;
              if (medicineValue) {
                const medicine = await Medicine.findById(medicineValue);
                if (medicine) {
                  medicine.quantity = Math.max(0, medicine.quantity - (item.cartQuantity || 1));
                  await medicine.save();
                  affectedIds.push(medicine._id);
                }
              }
            }
            order.stockReserved = true;
          }
          await order.save();
          if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
          await createNotification({
            userId: transaction.userId,
            title: 'Payment Accepted',
            message: `Your payment for order ${order._id} has been accepted.`,
            type: 'transaction',
            relatedId: order._id,
          });
          await sendPushToUser(transaction.userId, {
            title: 'Payment Accepted',
            body: `Your payment for order ${order._id} has been accepted.`,
            data: { type: 'transaction', orderId: String(order._id) },
          });

        // Mark related notifications as read
        await Notification.updateMany(
          { userId: transaction.userId, relatedId: order._id.toString(), type: 'order' },
          { $set: { read: true } }
        );
      } else {
        console.warn(`[API] No matching pending order found for transaction ${transaction._id}`);
      }
    } else if (status === 'Rejected' && previousStatus !== 'Rejected') {
      let order = null;
      if (transaction.orderId) {
        order = await Order.findById(transaction.orderId);
      } else {
        order = await Order.findOne({ userId: transaction.userId, status: 'pending' }).sort({ date: -1 });
      }

      if (order) {
        console.log(`[API] Updating order ${order._id} to rejected.`);
        const affectedIds = await releaseReservedStock(order);
        order.status = 'rejected';
        order.paymentStatus = 'unpaid'; // Explicitly unpaid if rejected
        order.statusUpdateHistory = order.statusUpdateHistory || [];
        order.statusUpdateHistory.push({ status: 'rejected', timestamp: getPKTDate() });
        await order.save();
        if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
        await createNotification({
          userId: transaction.userId,
          title: 'Payment Rejected',
          message: `Your payment for order ${order._id} was rejected.`,
          type: 'transaction',
          relatedId: order._id,
        });
        await sendPushToUser(transaction.userId, {
          title: 'Payment Rejected',
          body: `Your payment for order ${order._id} was rejected.`,
          data: { type: 'transaction', orderId: String(order._id) },
        });
      } else {
        console.warn(`[API] No matching order found for rejected transaction ${transaction._id}`);
      }
    }

    res.json(updatedTransaction);
  } catch (error) {
    console.error('Error updating transaction:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get all transaction history (all statuses)
app.get('/api/transactions/history/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });
    res.json(transactions);
  } catch (error) {
    console.error('Error retrieving transaction history:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get transaction summary (counts)
app.get('/api/transactions/summary/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const pendingCount = await Transaction.countDocuments({ userId, status: 'Pending' });
    const acceptedCount = await Transaction.countDocuments({ userId, status: 'Accepted' });
    const rejectedCount = await Transaction.countDocuments({ userId, status: 'Rejected' });

    const pendingTransactions = await Transaction.find({ userId, status: 'Pending' }).sort({ createdAt: -1 });
    const acceptedTransactions = await Transaction.find({ userId, status: 'Accepted' }).sort({ createdAt: -1 });
    const rejectedTransactions = await Transaction.find({ userId, status: 'Rejected' }).sort({ createdAt: -1 });

    res.json({
      counts: {
        pending: pendingCount,
        accepted: acceptedCount,
        rejected: rejectedCount
      },
      transactions: {
        pending: pendingTransactions,
        accepted: acceptedTransactions,
        rejected: rejectedTransactions
      }
    });
  } catch (error) {
    console.error('Error retrieving transaction summary:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Sync orders with accepted transactions - ensures order status matches transaction status
app.post('/api/orders/sync-transactions/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`[SYNC] Starting order-transaction sync for user: ${userId}`);

    // Find all accepted transactions for this user
    const acceptedTransactions = await Transaction.find({ userId, status: 'Accepted' });
    let syncedCount = 0;

    for (const txn of acceptedTransactions) {
      // Find orders linked to this transaction or by matching userId with pending status
      let order = null;

      if (txn.orderId) {
        order = await Order.findById(txn.orderId);
      }

      // If order is still pending, update it to accepted
      if (order && order.status === 'pending') {
        console.log(`[SYNC] Updating order ${order._id} from pending to accepted`);
        order.status = 'accepted';
        order.paymentStatus = 'paid';
        order.statusUpdateHistory = order.statusUpdateHistory || [];
        order.statusUpdateHistory.push({ status: 'accepted', timestamp: getPKTDate() });
        if (!order.stockReserved) {
          const affectedIds = [];
          for (const item of order.cartItems || []) {
            const medicineValue = item._id || item.id;
            if (!medicineValue) continue;
            const medicine = await Medicine.findById(medicineValue);
            if (medicine) {
              medicine.quantity = Math.max(0, Number(medicine.quantity || 0) - Number(item.cartQuantity || 0));
              await medicine.save();
              affectedIds.push(medicine._id);
            }
          }
          order.stockReserved = true;
          if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
        }
        await order.save();
        syncedCount++;
      }
    }

    // Also handle Rejected transactions: unlink and restore stock
    const rejectedTransactions = await Transaction.find({ userId, status: 'Rejected' });
    for (const txn of rejectedTransactions) {
      if (txn.orderId) {
        let order = await Order.findById(txn.orderId);
        if (order && order.status === 'pending') {
          console.log(`[SYNC] Unlinking rejected transaction ${txn._id} from order ${order._id}`);
          const affectedIds = await releaseReservedStock(order);
          order.transactionId = null; // Unlink so it shows as pending in UI
          order.status = 'rejected';
          order.paymentStatus = 'unpaid';
          order.statusUpdateHistory = order.statusUpdateHistory || [];
          order.statusUpdateHistory.push({ status: 'rejected', timestamp: getPKTDate() });
          await order.save();
          if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
        }
      }
    }

    // Also find orders with transactionId that points to an accepted transaction
    const ordersWithTransactionId = await Order.find({
      userId,
      status: 'pending',
      transactionId: { $ne: null, $exists: true }
    });

    for (const order of ordersWithTransactionId) {
      const transaction = await Transaction.findById(order.transactionId);
      if (transaction && transaction.status === 'Accepted') {
        console.log(`[SYNC] Updating order ${order._id} (via transactionId lookup) from pending to accepted`);
        order.status = 'accepted';
        order.paymentStatus = 'paid';
        order.statusUpdateHistory = order.statusUpdateHistory || [];
        order.statusUpdateHistory.push({ status: 'accepted', timestamp: getPKTDate() });
        if (!order.stockReserved) {
          const affectedIds = [];
          for (const item of order.cartItems || []) {
            const medicineValue = item._id || item.id;
            if (!medicineValue) continue;
            const medicine = await Medicine.findById(medicineValue);
            if (medicine) {
              medicine.quantity = Math.max(0, Number(medicine.quantity || 0) - Number(item.cartQuantity || 0));
              await medicine.save();
              affectedIds.push(medicine._id);
            }
          }
          order.stockReserved = true;
          if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
        }
        await order.save();
        syncedCount++;
      }
    }

    console.log(`[SYNC] Completed sync for ${userId}. Synced ${syncedCount} orders.`);
    res.json({ success: true, syncedCount, message: `Synced ${syncedCount} orders with accepted transactions` });
  } catch (error) {
    console.error('[SYNC] Error syncing orders:', error);
    res.status(500).json({ error: 'Failed to sync orders with transactions' });
  }
});

setInterval(async () => {
  try {
    const twentyMinutesAgo = new Date(Date.now() - 20 * 60 * 1000);
    const pendingTransactions = await Transaction.find({
      status: 'Pending',
      createdAt: { $lt: twentyMinutesAgo },
    });
    if (pendingTransactions.length > 0) {
      for (const txn of pendingTransactions) {
        txn.status = 'Rejected';
        await txn.save();
        console.log(`Transaction ${txn._id} automatically rejected due to timeout.`);

        if (txn.orderId) {
          const order = await Order.findById(txn.orderId);
          if (order && order.status === 'pending') {
            const affectedIds = await releaseReservedStock(order);
            order.status = 'rejected';
            order.paymentStatus = 'unpaid';
            order.statusUpdateHistory = order.statusUpdateHistory || [];
            order.statusUpdateHistory.push({ status: 'rejected', timestamp: getPKTDate() });
            await order.save();
            if (affectedIds.length) await pruneCartsForMedicines(affectedIds);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error auto-rejecting transactions:', error.message);
  }
}, 60 * 1000);

// Additional Routes
app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Both current and new password are required.' });
    }
    const user = req.user;
    if (!bcrypt.compareSync(currentPassword, user.password)) {
      return res.status(401).json({ message: 'Current password is incorrect.' });
    }
    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();
    res.json({ message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/usercount', async (req, res) => {
  try {
    const count = await User.countDocuments({});
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Server Start (Conditional for Vercel)
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  server.listen(PORT, '0.0.0.0', async () => {
    console.log(`Server running on port ${PORT}`);

    // Connect to MongoDB
    await connectDB();

    // Admin user setup
    try {
      const adminEmail1 = 'admin@mediapp.com';
      const defaultPassword1 = 'admin123';
      const hashedPassword1 = bcrypt.hashSync(defaultPassword1, 10);
      console.log('Attempting to set up admin user:', adminEmail1);

      let adminUser1 = await User.findOne({ email: adminEmail1 });
      if (adminUser1) {
        console.log('Existing admin user found:', adminUser1.email);
        adminUser1.password = hashedPassword1;
        adminUser1.role = 'admin';
        adminUser1.firstName = adminUser1.firstName || 'Admin';
        adminUser1.lastName = adminUser1.lastName || 'User';
        adminUser1.createdAt = adminUser1.createdAt || new Date().toISOString();
        await adminUser1.save();
        console.log('Admin user updated successfully (MediApp default).');
      } else {
        console.log('No existing admin user found. Creating new admin user.');
        adminUser1 = new User({
          id: uuidv4(),
          firstName: 'Admin',
          lastName: 'User',
          email: adminEmail1,
          password: hashedPassword1,
          role: 'admin',
          createdAt: new Date().toISOString(),
        });
        await adminUser1.save();
        console.log('New admin user created successfully (MediApp default):', adminUser1.email);
      }

      const adminEmail2 = 'admin@example.com';
      const existingAdmin2 = await User.findOne({ email: adminEmail2 });
      if (existingAdmin2) {
        console.log('Default admin user already exists (third server):', adminEmail2);
      } else {
        console.log('No default admin account exists (third server). Admin account creation is forbidden.');
      }
    } catch (err) {
      console.error('Error setting up admin users:', err.message, err.stack);
    }
    // Database migrations
    try {
      const medicinesWithoutType = await Medicine.find({ medicineType: { $exists: false } });
      if (medicinesWithoutType.length > 0) {
        console.log(`Found ${medicinesWithoutType.length} medicines without medicineType. Setting default to 'Tablet'.`);
        await Medicine.updateMany({ medicineType: { $exists: false } }, { $set: { medicineType: 'Tablet', dosesPerUnit: 1, remainingDoses: 0 } });
        console.log('Medicine types updated successfully.');
      }

      const medicinesWithoutDoses = await Medicine.find({ dosesPerUnit: { $exists: false } });
      if (medicinesWithoutDoses.length > 0) {
        console.log(`Found ${medicinesWithoutDoses.length} medicines without dosesPerUnit. Setting default to 1.`);
        await Medicine.updateMany({ dosesPerUnit: { $exists: false } }, { $set: { dosesPerUnit: 1, remainingDoses: 0 } });
        console.log('Doses per unit updated successfully.');
      }

      const medicinesWithoutRemaining = await Medicine.find({ remainingDoses: { $exists: false } });
      if (medicinesWithoutRemaining.length > 0) {
        console.log(`Found ${medicinesWithoutRemaining.length} medicines without remainingDoses. Setting default to 0.`);
        await Medicine.updateMany({ remainingDoses: { $exists: false } }, { $set: { remainingDoses: 0 } });
        console.log('Remaining doses updated successfully.');
      }
    } catch (err) {
      console.error('Error during migration:', err.message);
    }
  });
} else {
  // On Vercel
  connectDB().catch(err => console.error("Initial Vercel DB connect error:", err));
}

// Export for Vercel
module.exports = app;
