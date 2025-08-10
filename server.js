// server.js
require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fileUpload = require('express-fileupload');
const cloudinary = require('cloudinary').v2;
const bcrypt = require('bcryptjs');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 5000;

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(fileUpload({ useTempFiles: true }));

// ---------- Cloudinary ----------
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// ---------- MongoDB Setup ----------
const client = new MongoClient(process.env.MONGO_URI, {
  useUnifiedTopology: true,
});
const dbName = 'SecondHandEcomDB';

let db;
let usersCollection;
let productsCollection;
let ordersCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db(dbName);
    usersCollection = db.collection('users');
    productsCollection = db.collection('products');
    ordersCollection = db.collection('orders');
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
}

// ---------- JWT middleware ----------
function verifyToken(req, res, next) {
  try {
    const auth = req.headers.authorization || req.headers.Authorization;
    if (!auth) return res.status(401).send({ message: 'Unauthorized: No token' });

    const token = auth.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'Unauthorized: Malformed token' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).send({ message: 'Forbidden: Invalid token' });
      req.user = decoded; // { email, role, iat, exp }
      next();
    });
  } catch (err) {
    console.error('verifyToken error:', err);
    res.status(500).send({ message: 'Server error in auth' });
  }
}

// ---------- Swagger ----------
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: { title: 'Second-Hand Mobile E-Commerce API', version: '1.0.0' },
  },
  apis: ['./server.js'],
});
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ================== Auth Routes ==================

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Register a new user
 */
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, role, name } = req.body;
    if (!email || !password)
      return res.status(400).send({ message: 'Email and password required' });

    const existing = await usersCollection.findOne({ email });
    if (existing) return res.status(400).send({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const result = await usersCollection.insertOne({
      email,
      password: hashed,
      role: role || 'user',
      name: name || null,
      provider: 'local',
      createdAt: new Date(),
    });

    res.send({ message: 'User registered', userId: result.insertedId });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).send({ message: 'Server error registering user' });
  }
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Login and return JWT token
 */

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).send({ message: 'Email and password required' });

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(401).send({ message: 'Invalid credentials' });

    if (!user.password)
      return res.status(400).send({ message: 'Please login with your password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send({ message: 'Invalid credentials' });

    // Create JWT token (replace 'your_jwt_secret' with your actual secret)
    const token = jwt.sign(
      { email: user.email, role: user.role, name: user.name || null },
      'your_jwt_secret',
      { expiresIn: '1h' }
    );

    res.send({
      token,
      user: { email: user.email, role: user.role, name: user.name || null },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send({ message: 'Server error during login' });
  }
});


// ================== Product Routes ==================

/**
 * @swagger
 * /api/upload:
 *   post:
 *     summary: Upload product image to Cloudinary
 */
app.post('/api/upload', async (req, res) => {
  try {
    const file = req.files?.image;
    if (!file) return res.status(400).send({ message: 'No image uploaded' });

    const result = await cloudinary.uploader.upload(file.tempFilePath, {
      folder: 'ecom-secondhand',
    });

    res.send({ url: result.secure_url, public_id: result.public_id });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).send({ message: 'Image upload failed' });
  }
});

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Create a product (admin only)
 */
app.post('/api/products', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden: Admins only' });

    const product = req.body;
    product.createdAt = new Date();
    const result = await productsCollection.insertOne(product);
    res.send({ message: 'Product created', id: result.insertedId });
  } catch (err) {
    console.error('Create product error:', err);
    res.status(500).send({ message: 'Failed to create product' });
  }
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Get products (filter by category/company optional)
 */
app.get('/api/products', async (req, res) => {
  try {
    const { category, company, q } = req.query;

    const filter = {};
    if (category) filter.category = category;
    if (company) filter.company = company;
    if (q) {
      filter.$or = [
        { name: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } },
        { company: { $regex: q, $options: 'i' } },
      ];
    }

    const products = await productsCollection.find(filter).toArray();
    res.send(products);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).send({ message: 'Failed to fetch products' });
  }
});

/**
 * Update product by id
 */
app.put('/api/products/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updatedProduct = req.body;

    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden: Admins only' });

    const result = await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedProduct }
    );

    if (result.matchedCount === 0)
      return res.status(404).send({ message: 'Product not found' });

    res.send({ message: 'Product updated successfully' });
  } catch (err) {
    console.error('Update product error:', err);
    res.status(500).send({ message: 'Failed to update product' });
  }
});

/**
 * Delete product by id
 */
app.delete('/api/products/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden: Admins only' });

    const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0)
      return res.status(404).send({ message: 'Product not found' });
    res.send({ message: 'Product deleted' });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).send({ message: 'Failed to delete product' });
  }
});

// ================== Order Routes (protected) ==================

/**
 * Create order (protected)
 */
app.post('/api/orders', verifyToken, async (req, res) => {
  try {
    const order = req.body;
    order.email = req.user.email;
    order.date = new Date();
    const result = await ordersCollection.insertOne(order);
    res.send({ message: 'Order placed', id: result.insertedId });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).send({ message: 'Failed to create order' });
  }
});

/**
 * Get user orders (protected)
 */
app.get('/api/orders', verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const orders = await ordersCollection.find({ email }).toArray();
    res.send(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).send({ message: 'Failed to fetch orders' });
  }
});

// ================== Dashboard / Admin Routes ==================

/**
 * User dashboard overview (protected)
 */
app.get('/api/user/overview', verifyToken, async (req, res) => {
  try {
    const email = req.user.email;

    const totalCartProducts = await ordersCollection.countDocuments({
      email,
      $or: [{ status: 'pending' }, { status: 'cart' }],
    });

    const totalPurchasedProducts = await ordersCollection.countDocuments({
      email,
      $or: [{ status: 'completed' }, { status: 'purchased' }],
    });

    const latestOrder = await ordersCollection
      .find({ email })
      .sort({ date: -1 })
      .limit(1)
      .toArray();
    const latestOrderStatus = latestOrder.length ? latestOrder[0].status : null;

    const userProfile = await usersCollection.findOne(
      { email },
      { projection: { password: 0 } }
    );

    res.send({
      totalCartProducts,
      totalPurchasedProducts,
      latestOrderStatus,
      profile: userProfile || null,
    });
  } catch (err) {
    console.error('User overview error:', err);
    res.status(500).send({ message: 'Failed to fetch user overview' });
  }
});

/**
 * Admin dashboard overview (admin only)
 */
app.get('/api/admin/overview', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const totalUsers = await usersCollection.estimatedDocumentCount();
    const totalAdmins = await usersCollection.countDocuments({ role: 'admin' });
    const totalProducts = await productsCollection.estimatedDocumentCount();
    const totalSoldProducts = await ordersCollection.countDocuments({
      $or: [{ status: 'completed' }, { status: 'purchased' }],
    });

    res.send({
      totalUsers,
      totalAdmins,
      totalProducts,
      totalSoldProducts,
    });
  } catch (err) {
    console.error('Admin overview error:', err);
    res.status(500).send({ message: 'Failed to fetch admin overview' });
  }
});

/**
 * Get users (admin only)
 */
app.get('/api/admin/users', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
    res.send(users);
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).send({ message: 'Failed to fetch users' });
  }
});

/**
 * Promote user to admin (admin only)
 */
app.patch('/api/users/:id/promote', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid user id' });

    const result = await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role: 'admin' } }
    );

    if (result.matchedCount === 0) return res.status(404).send({ message: 'User not found' });

    res.send({ message: 'User promoted to admin' });
  } catch (err) {
    console.error('Promote user error:', err);
    res.status(500).send({ message: 'Failed to promote user' });
  }
});

/**
 * Get all orders (admin only)
 */
app.get('/api/admin/orders', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const allOrders = await ordersCollection.find().toArray();
    res.send(allOrders);
  } catch (err) {
    console.error('Admin get orders error:', err);
    res.status(500).send({ message: 'Server error' });
  }
});

/**
 * Admin stats
 */
app.get('/api/admin/stats', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const totalUsers = await usersCollection.estimatedDocumentCount();
    const totalOrders = await ordersCollection.estimatedDocumentCount();
    const totalProducts = await productsCollection.estimatedDocumentCount();

    res.send({ users: totalUsers, orders: totalOrders, products: totalProducts });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).send({ message: 'Server error' });
  }
});

/**
 * Admin recent orders
 */
app.get('/api/admin/recent-orders', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).send({ message: 'Forbidden' });

    const recentOrders = await ordersCollection.find().sort({ date: -1 }).limit(5).toArray();
    res.send(recentOrders);
  } catch (err) {
    console.error('Admin recent orders error:', err);
    res.status(500).send({ message: 'Server error' });
  }
});

// ================== Misc / Root ==================
app.get('/', (req, res) => {
  res.send('📱 Second-hand eCommerce Backend Running');
});

// ---------- Start server after DB connection ----------
(async () => {
  await connectDB();
  app.listen(port, () => {
    console.log(`🚀 Server running on http://localhost:${port}`);
    console.log(`📚 Swagger UI: http://localhost:${port}/api-docs`);
  });
})();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('SIGINT received: closing MongoDB connection');
  try {
    await client.close();
    console.log('MongoDB connection closed');
  } catch (err) {
    console.error('Error closing MongoDB:', err);
  }
  process.exit(0);
});
