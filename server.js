const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const fileUpload = require('express-fileupload');
const cloudinary = require('cloudinary').v2;
const bcrypt = require('bcryptjs');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(fileUpload({ useTempFiles: true }));

// MongoDB Config
const client = new MongoClient(process.env.MONGO_URI);
const dbName = 'SecondHandEcomDB';
let db, usersCollection, productsCollection, ordersCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db(dbName);
    usersCollection = db.collection('users');
    productsCollection = db.collection('products');
    ordersCollection = db.collection('orders');
    console.log('✅ MongoDB Connected');
  } catch (error) {
    console.error('MongoDB connection failed:', error);
  }
}

// JWT Verify
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send('Unauthorized');
  const token = auth.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send('Forbidden');
    req.user = decoded;
    next();
  });
}

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// Swagger Docs
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Second-Hand Mobile E-Commerce API',
      version: '1.0.0',
    },
  },
  apis: ['./server.js'],
});
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ================== Auth Routes ================== //

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Register a new user
 */
app.post('/api/register', async (req, res) => {
  const { email, password, role } = req.body;
  const user = await usersCollection.findOne({ email });
  if (user) return res.status(400).send('User already exists');
  const hashedPassword = await bcrypt.hash(password, 10);
  await usersCollection.insertOne({ email, password: hashedPassword, role: role || 'user' });
  res.send({ message: 'User registered' });
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Login and return JWT token
 */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(401).send('Invalid credentials');
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).send('Invalid credentials');
  const token = jwt.sign({ email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.send({ token });
});

// ================== Product Routes ================== //

app.post('/api/upload', async (req, res) => {
  const file = req.files?.image;
  if (!file) return res.status(400).send('No image uploaded');
  const result = await cloudinary.uploader.upload(file.tempFilePath, {
    folder: 'ecom-secondhand',
  });
  res.send({ url: result.secure_url });
});

app.post('/api/products',  async (req, res) => {
  const product = req.body;
  const result = await productsCollection.insertOne(product);
  res.send(result);
});

app.get('/api/products', async (req, res) => {
  const category = req.query.category;
  const company = req.query.company;

  let filter = {};
  if (category) filter.category = category;
  if (company) filter.company = company;

  const result = await productsCollection.find(filter).toArray();
  res.send(result);
});
// Update product by id
app.put('/api/products/:id',  async (req, res) => {
  try {
    const { id } = req.params;
    const updatedProduct = req.body;

    // Optional: You can validate fields here before updating

    const result = await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedProduct }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'Product not found' });
    }

    res.send({ message: 'Product updated successfully' });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).send({ message: 'Failed to update product' });
  }
});


app.delete('/api/products/:id', async (req, res) => {
  const result = await productsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
  res.send(result);
});

// ================== Order Routes ================== //

app.post('/api/orders',  async (req, res) => {
  const order = req.body;
  order.email = req.user.email;
  order.date = new Date();
  const result = await ordersCollection.insertOne(order);
  res.send(result);
});

app.get('/api/orders',  async (req, res) => {
  const email = req.user.email;
  const result = await ordersCollection.find({ email }).toArray();
  res.send(result);
});

// ================== Admin Routes ================== //

app.get('/api/admin/orders',  async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  const result = await ordersCollection.find().toArray();
  res.send(result);
});

// 🔹 Admin Dashboard Stats
app.get('/api/admin/stats',  async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).send('Forbidden');

    const totalUsers = await usersCollection.estimatedDocumentCount();
    const totalOrders = await ordersCollection.estimatedDocumentCount();
    const totalProducts = await productsCollection.estimatedDocumentCount();

    res.send({
      users: totalUsers,
      orders: totalOrders,
      products: totalProducts
    });
  } catch (err) {
    res.status(500).send('Server error while fetching stats');
  }
});

// 🔹 Admin Dashboard Recent Orders
app.get('/api/admin/recent-orders',  async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).send('Forbidden');

    const recentOrders = await ordersCollection
      .find()
      .sort({ date: -1 })
      .limit(5)
      .toArray();

    res.send(recentOrders);
  } catch (err) {
    res.status(500).send('Server error while fetching recent orders');
  }
});

// ================== Root ================== //
app.get('/', (req, res) => {
  res.send('📱 Second-hand eCommerce Backend Running');
});

// ================== Start Server ================== //
app.listen(port, () => {
  connectDB();
  console.log(`🚀 Server is running on http://localhost:${port}`);
});
