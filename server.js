require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 2000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secure_secret_key_here'; // Replace with a strong secret in production

// Create HTTP server and Socket.IO instance
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

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

// Multer setup for file uploads (general - medicines etc might still need local or separate setup)
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
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    transformation: [{ width: 500, height: 500, crop: 'limit' }],
  },
});
const uploadProfile = multer({ storage: profileStorage });

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
const Settings = mongoose.model('Settings', SettingsSchema);

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
  createdAt: { type: Date, default: Date.now },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  dob: { type: String, default: '' },
});
const User = mongoose.model('User', userSchema);

// Category Schema
const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
});
const Category = mongoose.model('Category', CategorySchema);

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
});
const Medicine = mongoose.model('Medicine', MedicineSchema);

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
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  date: { type: Date, default: Date.now },
  transactionId: { type: String, default: null },
  paymentStatus: { type: String, enum: ['paid', 'unpaid'], default: 'unpaid' },
  statusUpdateHistory: [{ status: String, timestamp: { type: Date, default: Date.now } }],
});
const Order = mongoose.model('Order', OrderSchema);

// Cart Schema
const CartSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  cart: { type: Array, default: [] },
});
const Cart = mongoose.model('Cart', CartSchema);

// In-Person Sale Schema
const InPersonSaleSchema = new mongoose.Schema({
  medicineId: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine', required: true },
  medicineName: { type: String, required: true },
  quantitySold: { type: Number, required: true },
  unitType: { type: String, required: true },
  saleDate: { type: Date, default: Date.now },
  customerName: { type: String },
  customerContact: { type: String },
  adminId: { type: String, required: true },
  totalAmount: { type: Number, required: true },
});
const InPersonSale = mongoose.model('InPersonSale', InPersonSaleSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  walletNumber: { type: String, required: true },
  walletName: { type: String, required: true },
  transactionID: { type: String, required: true },
  depositAmount: { type: Number, required: true },
  status: { type: String, enum: ['Accepted', 'Rejected', 'Pending'], default: 'Pending' },
  createdAt: { type: Date, default: Date.now },
});
const Transaction = mongoose.model('Transaction', transactionSchema);

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
    console.log('Token received:', req.headers.authorization);
    console.log('--- AUTH ERROR END ---');
    return res.status(401).json({
      message: 'Invalid token',
      error: err.message,
      server_type: 'MEDICINE_BACKEND_LATEST'
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
    res.status(500).json({ error: 'Server error' });
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
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/cart', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const cart = await Cart.findOne({ userId });
    res.json({ cartItems: cart ? cart.cart : [] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/cart', async (req, res) => {
  try {
    const { userId, cart } = req.body;
    if (!userId || !Array.isArray(cart)) return res.status(400).json({ error: 'Invalid request data' });
    let userCart = await Cart.findOne({ userId });
    if (userCart) {
      userCart.cart = cart;
      await userCart.save();
    } else {
      userCart = new Cart({ userId, cart });
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
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const orders = await Order.find({ userId }).sort({ date: -1 });
    res.json({ orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/order', async (req, res) => {
  try {
    const { userId, shippingEmail, billingEmail, shippingAddress, billingAddress, shippingMethod, paymentMethod, cartItems, shippingFee, orderTotal, location } = req.body;
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

    if (order.transactionId && order.paymentMethod.toLowerCase() === 'easypaisa') {
      const transaction = await Transaction.findById(order.transactionId);
      if (transaction && transaction.status === 'Accepted') {
        order.status = 'accepted';
        order.paymentStatus = 'paid';
        order.statusUpdateHistory = order.statusUpdateHistory || [];
        order.statusUpdateHistory.push({ status: 'accepted', timestamp: new Date() });
      } else {
        order.status = 'accepted';
        order.statusUpdateHistory = order.statusUpdateHistory || [];
        order.statusUpdateHistory.push({ status: 'accepted', timestamp: new Date() });
      }
    } else {
      order.status = 'accepted';
      order.statusUpdateHistory = order.statusUpdateHistory || [];
      order.statusUpdateHistory.push({ status: 'accepted', timestamp: new Date() });
    }

    for (let item of order.cartItems) {
      const medicine = await Medicine.findById(item._id || item.id);
      if (medicine) {
        medicine.quantity -= item.cartQuantity;
        await medicine.save();
      }
    }

    await order.save();
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
    order.status = 'rejected';
    await order.save();
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

app.post('/admin/add-medicine', authAdminPage, upload1.single('image'), async (req, res) => {
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

    const image = req.file ? '/uploads/' + req.file.filename : null;

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

app.post('/admin/medicines/:id/edit', authAdminPage, upload1.single('image'), async (req, res) => {
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
    if (req.file) medicine.image = '/uploads/' + req.file.filename;
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
  timestamp: { type: Date, default: Date.now },
});
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

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
      callback({ success: true });
    } catch (err) {
      console.error('Error saving message:', err.message);
      callback({ error: err.message });
    }

  });

  socket.on('disconnect', () => console.log('User disconnected:', socket.id));
});

// Chat Routes
app.post('/chat/upload', authMiddleware, upload1.single('file'), async (req, res) => {
  try {
    const { userId, type, receiver } = req.body;
    console.log('POST /chat/upload: Received data:', { userId, type, receiver, hasFile: !!req.file });
    if (!userId || !type || !receiver) {
      console.error('POST /chat/upload: Missing required fields');
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!['image', 'document', 'voice'].includes(type)) {
      console.error('POST /chat/upload: Invalid message type:', type);
      return res.status(400).json({ error: 'Invalid message type' });
    }
    if (!req.file) {
      console.error('POST /chat/upload: No file uploaded');
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const messageContent = `/Uploads/${req.file.filename}`;
    const newMsg = new ChatMessage({
      _id: new mongoose.Types.ObjectId().toString(),
      sender: userId,
      receiver,
      type,
      content: messageContent,
      timestamp: new Date(),
    });
    await newMsg.save();
    console.log('POST /chat/upload: Message saved to MongoDB:', newMsg);
    io.to(receiver).emit('receiveMessage', newMsg);
    io.to(userId).emit('receiveMessage', newMsg);
    res.status(200).json({ message: 'File uploaded and message sent successfully', url: messageContent });
  } catch (err) {
    console.error('POST /chat/upload: Error:', err.message);
    res.status(500).json({ error: 'Failed to upload file: ' + err.message });
  }
});

app.get('/api/messages/admin', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
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

app.get('/admin/chat', authAdminPage, async (req, res) => {
  try {
    const users = await User.find({ role: 'user' }).select('id firstName lastName email');
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

app.post('/admin/chat/send', authAdminPage, upload1.single('file'), async (req, res) => {
  try {
    const { userId, type, content } = req.body;
    console.log('POST /admin/chat/send: Received data:', { userId, type, content, hasFile: !!req.file });
    if (!userId) {
      console.error('POST /admin/chat/send: Missing userId');
      return res.status(400).json({ error: 'Missing userId' });
    }
    if (!type || !['text', 'image', 'document', 'voice'].includes(type)) {
      console.error('POST /admin/chat/send: Invalid message type:', type);
      return res.status(400).json({ error: 'Invalid message type' });
    }
    let messageContent = content;
    if (req.file && ['image', 'document', 'voice'].includes(type)) {
      messageContent = `/Uploads/${req.file.filename}`;
      console.log('POST /admin/chat/send: File uploaded:', messageContent);
    } else if (type === 'text' && !content) {
      console.error('POST /admin/chat/send: Text message content is empty');
      return res.status(400).json({ error: 'Text message cannot be empty' });
    }
    const newMsg = new ChatMessage({
      _id: new mongoose.Types.ObjectId().toString(),
      sender: 'admin',
      receiver: userId,
      type,
      content: messageContent,
      timestamp: new Date(),
    });
    await newMsg.save();
    console.log('POST /admin/chat/send: Message saved to MongoDB:', newMsg);
    io.to(userId).emit('receiveMessage', newMsg);
    io.to('admin').emit('receiveMessage', newMsg);
    res.status(200).json({ message: 'Message sent successfully' });
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
  createdAt: { type: Date, default: Date.now },
});
const Feedback = mongoose.model('Feedback', FeedbackSchema);

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
  medicineId: { type: mongoose.Schema.Types.ObjectId, ref: 'Medicine', required: true },
  medicineName: { type: String, required: true },
  dosage: { type: String, required: true },
  time: { type: String, required: true }, // e.g., "08:00 AM"
  date: { type: Date, required: true },
  repeat: { type: String, enum: ['None', 'Daily', 'Weekly'], default: 'None' },
  notes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const MedicineReminder = mongoose.model('MedicineReminder', medicineReminderSchema);

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
    const { medicineId, medicineName, dosage, time, date, repeat, notes } = req.body;
    if ((!medicineId && !medicineName) || !dosage || !time || !date) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    let medName = medicineName;
    if (medicineId) {
      const medicine = await Medicine.findById(medicineId);
      if (!medicine) return res.status(404).json({ error: 'Medicine not found' });
      medName = medicine.name;
    }

    const reminder = new MedicineReminder({
      userId: req.user.id,
      medicineId: medicineId || null,
      medicineName: medName,
      dosage,
      time,
      date,
      repeat,
      notes
    });
    await reminder.save();
    res.status(201).json({ message: 'Reminder created successfully', reminder });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create reminder', details: err.message });
  }
});


// Get reminders for logged-in user
app.get('/api/reminders', authMiddleware, async (req, res) => {
  try {
    const reminders = await MedicineReminder.find({ userId: req.user.id }).sort({ date: 1, time: 1 });
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
    const { userId, walletNumber, walletName, transactionID, depositAmount } = req.body;
    if (!userId || !walletNumber || !walletName || !transactionID || !depositAmount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newTransaction = new Transaction({
      userId,
      walletNumber,
      walletName,
      transactionID,
      depositAmount: parseFloat(depositAmount),
    });

    const savedTransaction = await newTransaction.save();
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
    const updatedTransaction = await Transaction.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!updatedTransaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json(updatedTransaction);
  } catch (error) {
    console.error('Error updating transaction:', error);
    res.status(500).json({ error: 'Internal Server Error' });
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