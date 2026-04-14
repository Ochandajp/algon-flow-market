const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS enabled for all origins
app.use(cors({ origin: '*', credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());
app.use(express.static(__dirname));

// NEW MongoDB URL
const MONGODB_URI = 'mongodb+srv://Lazermarkets:Shaku@cluster0.llhd1bp.mongodb.net/lazermarkets?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// ============= SCHEMAS =============
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    age: { type: Number, required: true },
    country: { type: String, required: true },
    countryCode: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    employmentStatus: { type: String, enum: ['Employed', 'Self-Employed', 'Unemployed', 'Student', 'Retired'], required: true },
    tradingExperience: { type: String, enum: ['Beginner', 'Intermediate', 'Expert'], required: true },
    fundsSource: { type: String, enum: ['Personal Savings', 'Business Revenue', 'Inheritance or Gift', 'Loan Proceeds', 'Investment from Partners/Investors', 'Sale of Assets'], required: true },
    balance: { type: Number, default: 0 },
    totalDeposits: { type: Number, default: 0 },
    totalProfit: { type: Number, default: 0 },
    totalLoss: { type: Number, default: 0 },
    winRate: { type: Number, default: 0 },
    totalTrades: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    isAdmin: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    withdrawalAddress: { type: String, default: '' },
    termsAccepted: { type: Boolean, required: true },
    termsAcceptedAt: { type: Date },
    isFromUSA: { type: String, default: 'no' },
    expectedDeposit: { type: String, default: '' },
    aiApiKey: { type: String, default: '' }
});

const tradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    symbol: { type: String, required: true },
    symbolName: { type: String, required: true },
    category: { type: String, required: true },
    side: { type: String, enum: ['buy', 'sell'], required: true },
    amount: { type: Number, required: true },
    leverage: { type: Number, default: 1 },
    duration: { type: String, required: true },
    durationMs: { type: Number, required: true },
    entryPrice: { type: Number, required: true },
    exitPrice: { type: Number, default: null },
    profit: { type: Number, default: null },
    status: { type: String, enum: ['active', 'completed', 'stopped'], default: 'active' },
    analysis: { type: String, default: '' },
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date },
    aiPasskey: { type: String }
});

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'profit', 'trade', 'admin_deposit', 'admin_deduct'], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    transactionId: { type: String, unique: true },
    description: { type: String },
    adminName: { type: String },
    withdrawalFee: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    amount: { type: Number, required: true },
    feeAmount: { type: Number, default: 0 },
    network: { type: String, required: true },
    walletAddress: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    processedBy: { type: String }
});

const User = mongoose.model('User', userSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ============= MIDDLEWARE =============
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET || 'lazermarkets_jwt_secret');
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

const isAdmin = async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    next();
};

function generatePasskey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let passkey = '';
    for (let i = 0; i < 12; i++) {
        passkey += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return passkey;
}

// ============= AUTH ROUTES =============
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, fullName, age, country, countryCode, phoneNumber, employmentStatus, tradingExperience, fundsSource, termsAccepted, isFromUSA, expectedDeposit } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already registered' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email, password: hashedPassword, fullName, age, country, countryCode, phoneNumber,
            employmentStatus, tradingExperience, fundsSource, termsAccepted, termsAcceptedAt: new Date(),
            isFromUSA: isFromUSA || 'no', expectedDeposit: expectedDeposit || '', balance: 0,
            isAdmin: email === 'admin@lazermarkets.com'
        });
        await user.save();
        const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'lazermarkets_jwt_secret');
        res.status(201).json({ success: true, token, user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin } });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid email or password' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid email or password' });
        user.lastLogin = new Date();
        await user.save();
        const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'lazermarkets_jwt_secret');
        res.json({ success: true, token, user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin } });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// AI PASSKEY ROUTES
app.post('/api/admin/generate-passkey/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const newPasskey = generatePasskey();
        user.aiApiKey = newPasskey;
        await user.save();
        res.json({ success: true, passkey: newPasskey });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate passkey' });
    }
});

app.delete('/api/admin/delete-passkey/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.aiApiKey = '';
        await user.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete passkey' });
    }
});

app.post('/api/ai/save-passkey', authenticateToken, async (req, res) => {
    try {
        const { passkey } = req.body;
        if (!passkey || passkey.trim() === '') return res.status(400).json({ error: 'Passkey cannot be empty' });
        await User.findByIdAndUpdate(req.user.id, { aiApiKey: passkey });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save passkey' });
    }
});

app.delete('/api/ai/delete-passkey', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { aiApiKey: '' });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete passkey' });
    }
});

app.get('/api/ai/get-passkey', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ success: true, passkey: user.aiApiKey || '' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get passkey' });
    }
});

// AI TRADE ROUTES
app.post('/api/ai/start-trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, symbolName, category, amount, leverage, duration, durationMs, passkey } = req.body;
        const user = await User.findById(req.user.id);
        if (user.aiApiKey !== passkey) return res.status(400).json({ error: 'Invalid AI Passkey' });
        if (amount < 115) return res.status(400).json({ error: 'Minimum AI trade amount is $115 USD' });
        if (amount > user.balance) return res.status(400).json({ error: 'Insufficient balance' });
        
        let currentPrice = 50000;
        let change24h = 0;
        try {
            if (category === 'crypto') {
                const response = await axios.get(`https://api.binance.com/api/v3/ticker/24hr?symbol=${symbol}`);
                currentPrice = parseFloat(response.data.lastPrice);
                change24h = parseFloat(response.data.priceChangePercent);
            }
        } catch(e) {}
        
        const side = Math.random() > 0.5 ? 'buy' : 'sell';
        user.balance = user.balance - amount;
        await user.save();
        
        const trade = new Trade({
            userId: user._id, symbol, symbolName, category, side, amount, leverage, duration, durationMs,
            entryPrice: currentPrice, analysis: 'AI Analysis Complete', aiPasskey: passkey, status: 'active'
        });
        await trade.save();
        
        res.json({ success: true, trade, analysis: { decision: side, confidence: 75, entryPrice: currentPrice, reasons: ['Market analysis complete'], signals: ['Trade executed'] } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to start AI trade' });
    }
});

app.post('/api/ai/stop-trade/:tradeId', authenticateToken, async (req, res) => {
    try {
        const trade = await Trade.findOne({ _id: req.params.tradeId, userId: req.user.id, status: 'active' });
        if (!trade) return res.status(404).json({ error: 'Active trade not found' });
        trade.status = 'stopped';
        trade.endedAt = new Date();
        let profit = (Math.random() - 0.5) * 30;
        trade.profit = profit;
        await trade.save();
        const user = await User.findById(req.user.id);
        if (user) {
            user.balance = user.balance + trade.amount + profit;
            if (profit > 0) user.totalProfit += profit;
            else user.totalLoss += Math.abs(profit);
            user.totalTrades += 1;
            await user.save();
        }
        res.json({ success: true, profit });
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop trade' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const activeTrades = await Trade.find({ userId: req.user.id, status: 'active' });
        const tradeHistory = await Trade.find({ userId: req.user.id, status: 'completed' }).sort({ endedAt: -1 }).limit(50);
        res.json({ user, activeTrades, tradeHistory });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// DEPOSIT
app.post('/api/deposit/create', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        if (amount < 60) return res.status(400).json({ error: 'Minimum deposit is $60 USD' });
        const paymentId = 'DEP_' + Date.now();
        const transaction = new Transaction({ userId: req.user.id, userName: (await User.findById(req.user.id)).fullName, type: 'deposit', amount, status: 'pending', transactionId: paymentId });
        await transaction.save();
        res.json({ success: true, paymentId });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create deposit' });
    }
});

app.get('/api/deposit/check/:paymentId', authenticateToken, async (req, res) => {
    try {
        const transaction = await Transaction.findOne({ transactionId: req.params.paymentId });
        if (transaction && transaction.status === 'pending') {
            transaction.status = 'completed';
            await transaction.save();
            const user = await User.findById(transaction.userId);
            if (user) {
                user.balance += transaction.amount;
                user.totalDeposits += transaction.amount;
                await user.save();
            }
        }
        res.json({ status: transaction?.status || 'not_found' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check status' });
    }
});

// WITHDRAWAL
app.post('/api/withdrawal/request', authenticateToken, async (req, res) => {
    try {
        const { amount, network, address } = req.body;
        const user = await User.findById(req.user.id);
        if (amount < 50) return res.status(400).json({ error: 'Minimum withdrawal is $50' });
        const feeAmount = amount * 0.02;
        if (amount > user.balance) return res.status(400).json({ error: 'Insufficient balance' });
        user.balance = user.balance - amount;
        await user.save();
        const withdrawal = new Withdrawal({ userId: user._id, userName: user.fullName, amount, feeAmount, network, walletAddress: address, status: 'pending' });
        await withdrawal.save();
        res.json({ success: true, feeAmount, netAmount: amount - feeAmount });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// ADMIN ROUTES
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json(users);
});

app.get('/api/admin/users/:userId', authenticateToken, isAdmin, async (req, res) => {
    const user = await User.findById(req.params.userId).select('-password');
    const transactions = await Transaction.find({ userId: req.params.userId }).sort({ createdAt: -1 }).limit(20);
    res.json({ user, transactions });
});

app.post('/api/admin/add-balance', authenticateToken, isAdmin, async (req, res) => {
    const { userId, amount, description } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.balance += amount;
    user.totalDeposits += amount;
    await user.save();
    await Transaction.create({ userId: user._id, userName: user.fullName, type: 'admin_deposit', amount, transactionId: 'ADMIN_' + Date.now(), description, adminName: 'Admin' });
    res.json({ success: true, newBalance: user.balance });
});

app.post('/api/admin/deduct-balance', authenticateToken, isAdmin, async (req, res) => {
    const { userId, amount, description } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    user.balance -= amount;
    await user.save();
    await Transaction.create({ userId: user._id, userName: user.fullName, type: 'admin_deduct', amount, transactionId: 'ADMIN_WD_' + Date.now(), description, adminName: 'Admin' });
    res.json({ success: true, newBalance: user.balance });
});

app.put('/api/admin/users/:userId/toggle-status', authenticateToken, isAdmin, async (req, res) => {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.isActive = !user.isActive;
    await user.save();
    res.json({ success: true, isActive: user.isActive });
});

app.get('/api/admin/transactions', authenticateToken, isAdmin, async (req, res) => {
    const transactions = await Transaction.find().sort({ createdAt: -1 }).limit(100);
    res.json(transactions);
});

app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
    const withdrawals = await Withdrawal.find().sort({ createdAt: -1 });
    res.json(withdrawals);
});

app.post('/api/admin/withdrawals/:withdrawalId/process', authenticateToken, isAdmin, async (req, res) => {
    const { status } = req.body;
    const withdrawal = await Withdrawal.findById(req.params.withdrawalId);
    if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
    withdrawal.status = status;
    withdrawal.processedAt = new Date();
    await withdrawal.save();
    if (status === 'rejected') {
        const user = await User.findById(withdrawal.userId);
        if (user) user.balance += withdrawal.amount;
        await user.save();
    }
    res.json({ success: true });
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalBalance = (await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]))[0]?.total || 0;
    const totalProfit = (await User.aggregate([{ $group: { _id: null, total: { $sum: '$totalProfit' } } }]))[0]?.total || 0;
    res.json({ totalUsers, activeUsers, totalBalance, totalProfit });
});

// CREATE DEFAULT ADMIN
async function createDefaultAdmin() {
    const adminExists = await User.findOne({ email: 'admin@lazermarkets.com' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('Admin123!', 10);
        const admin = new User({
            email: 'admin@lazermarkets.com', password: hashedPassword, fullName: 'System Administrator', age: 30,
            country: 'United States', countryCode: '+1', phoneNumber: '1234567890', employmentStatus: 'Employed',
            tradingExperience: 'Expert', fundsSource: 'Business Revenue', termsAccepted: true, isAdmin: true, balance: 10000, aiApiKey: 'ADMIN2024KEY'
        });
        await admin.save();
        console.log('✅ Default admin created: admin@lazermarkets.com / Admin123!');
    }
}

// Serve HTML files
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/deposit', (req, res) => res.sendFile(path.join(__dirname, 'deposit.html')));
app.get('/withdraw', (req, res) => res.sendFile(path.join(__dirname, 'withdraw.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, async () => {
    await createDefaultAdmin();
    console.log(`🚀 LazerMarkets server running on port ${PORT}`);
    console.log(`📱 Backend API available at: https://lazermarkets.onrender.com`);
});