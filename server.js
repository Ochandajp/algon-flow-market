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

// CRITICAL: Allow ALL origins - this allows any frontend (local, Netlify, Vercel) to connect
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static(__dirname));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://officialwrittershub_db_user:Fellix@cluster0.6g8mg9p.mongodb.net/algonflow?retryWrites=true&w=majority';

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
        const verified = jwt.verify(token, process.env.JWT_SECRET || 'algonflow_jwt_secret');
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

// Helper function to generate 12-digit alphanumeric passkey
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
            email,
            password: hashedPassword,
            fullName,
            age,
            country,
            countryCode,
            phoneNumber,
            employmentStatus,
            tradingExperience,
            fundsSource,
            termsAccepted,
            termsAcceptedAt: new Date(),
            isFromUSA: isFromUSA || 'no',
            expectedDeposit: expectedDeposit || '',
            balance: 0,
            isAdmin: email === 'admin@algonflow.com'
        });
        
        await user.save();
        
        const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'algonflow_jwt_secret');
        
        res.status(201).json({ 
            success: true, 
            token, 
            user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin }
        });
    } catch (error) {
        console.error(error);
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
        
        const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'algonflow_jwt_secret');
        
        res.json({ 
            success: true, 
            token, 
            user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// ============= AI PASSKEY ROUTES =============
// Admin: Generate a new passkey for a user
app.post('/api/admin/generate-passkey/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        const newPasskey = generatePasskey();
        user.aiApiKey = newPasskey;
        await user.save();
        
        res.json({ success: true, passkey: newPasskey, message: `Passkey generated for ${user.fullName}` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate passkey' });
    }
});

// Admin: Delete/Revoke passkey for a user
app.delete('/api/admin/delete-passkey/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.aiApiKey = '';
        await user.save();
        
        res.json({ success: true, message: `Passkey revoked for ${user.fullName}` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete passkey' });
    }
});

// User: Save their own passkey
app.post('/api/ai/save-passkey', authenticateToken, async (req, res) => {
    try {
        const { passkey } = req.body;
        if (!passkey || passkey.trim() === '') {
            return res.status(400).json({ error: 'Passkey cannot be empty' });
        }
        await User.findByIdAndUpdate(req.user.id, { aiApiKey: passkey });
        res.json({ success: true, message: 'Passkey saved successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save passkey' });
    }
});

// User: Delete their own passkey
app.delete('/api/ai/delete-passkey', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { aiApiKey: '' });
        res.json({ success: true, message: 'Passkey deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete passkey' });
    }
});

// User: Get their own passkey
app.get('/api/ai/get-passkey', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ success: true, passkey: user.aiApiKey || '' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get passkey' });
    }
});

function analyzeMarket(symbol, currentPrice, change24h, volume, volatility) {
    const analysis = {
        decision: null,
        confidence: 0,
        reasons: [],
        signals: []
    };
    
    const rsi = 30 + Math.random() * 70;
    const macd = (Math.random() - 0.5) * 2;
    
    analysis.reasons.push(`📊 RSI: ${rsi.toFixed(2)} - ${rsi < 30 ? 'Oversold' : rsi > 70 ? 'Overbought' : 'Neutral'}`);
    analysis.reasons.push(`📈 MACD: ${macd > 0 ? 'Bullish' : 'Bearish'}`);
    analysis.reasons.push(`💰 24h Change: ${change24h > 0 ? '+' : ''}${change24h.toFixed(2)}%`);
    analysis.reasons.push(`⚡ Volume: ${volume > 1000000 ? 'High' : 'Normal'}`);
    analysis.reasons.push(`📉 Volatility: ${volatility > 2 ? 'High' : 'Normal'}`);
    
    let buyScore = 0;
    let sellScore = 0;
    
    if (rsi < 40) buyScore += 30;
    if (rsi > 60) sellScore += 30;
    if (macd > 0) buyScore += 25;
    if (macd < 0) sellScore += 25;
    if (change24h > 0) buyScore += 20;
    if (change24h < -2) sellScore += 20;
    if (volatility > 2) buyScore += 15;
    
    if (buyScore > sellScore) {
        analysis.decision = 'buy';
        analysis.confidence = Math.min(95, Math.max(55, 55 + (buyScore - sellScore)));
        analysis.signals.push('🚀 Bullish momentum detected');
        analysis.signals.push('🎯 Entry point identified');
    } else {
        analysis.decision = 'sell';
        analysis.confidence = Math.min(95, Math.max(55, 55 + (sellScore - buyScore)));
        analysis.signals.push('📉 Bearish pressure building');
        analysis.signals.push('⚠️ Resistance level approaching');
    }
    
    return analysis;
}

async function updateActiveTrades() {
    const activeTrades = await Trade.find({ status: 'active' });
    
    for (const trade of activeTrades) {
        const elapsed = Date.now() - new Date(trade.startedAt).getTime();
        const progress = Math.min(1, elapsed / trade.durationMs);
        
        let simulatedPrice = trade.entryPrice;
        if (trade.side === 'buy') {
            const volatility = 0.002;
            const trend = 0.0005;
            simulatedPrice = trade.entryPrice * (1 + (progress * trend) + (Math.random() - 0.5) * volatility);
        } else {
            const volatility = 0.002;
            const trend = -0.0005;
            simulatedPrice = trade.entryPrice * (1 + (progress * trend) + (Math.random() - 0.5) * volatility);
        }
        
        trade.exitPrice = simulatedPrice;
        
        let profit = 0;
        if (trade.side === 'buy') {
            profit = (simulatedPrice - trade.entryPrice) / trade.entryPrice * trade.amount * trade.leverage;
        } else {
            profit = (trade.entryPrice - simulatedPrice) / trade.entryPrice * trade.amount * trade.leverage;
        }
        
        if (profit < -10) {
            profit = -10;
        }
        
        if (profit > 0 && profit < 15) {
            profit = 15 + Math.random() * 20;
        }
        
        trade.profit = profit;
        
        if (elapsed >= trade.durationMs || Math.abs(profit) >= trade.amount * 0.83) {
            trade.status = 'completed';
            trade.endedAt = new Date();
            
            const user = await User.findById(trade.userId);
            if (user) {
                const amountToReturn = trade.amount + profit;
                user.balance = user.balance + amountToReturn;
                
                if (profit > 0) {
                    user.totalProfit = (user.totalProfit || 0) + profit;
                } else {
                    user.totalLoss = (user.totalLoss || 0) + Math.abs(profit);
                }
                user.totalTrades = (user.totalTrades || 0) + 1;
                
                const completedTrades = await Trade.find({ userId: trade.userId, status: 'completed' });
                const wins = completedTrades.filter(t => t.profit > 0).length;
                user.winRate = completedTrades.length > 0 ? (wins / completedTrades.length) * 100 : 0;
                
                await user.save();
                
                const transaction = new Transaction({
                    userId: user._id,
                    userName: user.fullName,
                    type: 'profit',
                    amount: Math.abs(profit),
                    transactionId: 'TRADE_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
                    description: `${trade.side.toUpperCase()} trade on ${trade.symbolName} completed. ${profit >= 0 ? 'Profit' : 'Loss'}: $${Math.abs(profit).toFixed(2)}`
                });
                await transaction.save();
            }
        }
        
        await trade.save();
    }
}

setInterval(updateActiveTrades, 5000);

// ============= AI START TRADE (Minimum $115 required) =============
app.post('/api/ai/start-trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, symbolName, category, amount, leverage, duration, durationMs, passkey } = req.body;
        
        const user = await User.findById(req.user.id);
        
        if (user.aiApiKey !== passkey) {
            return res.status(400).json({ error: 'Invalid AI Passkey' });
        }
        
        // MINIMUM $115 FOR AI TRADING
        if (amount < 115) {
            return res.status(400).json({ error: 'Minimum AI trade amount is $115 USD' });
        }
        
        if (amount > user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        let currentPrice = 0;
        let change24h = 0;
        let volume = 0;
        
        try {
            if (category === 'crypto') {
                const response = await axios.get(`https://api.binance.com/api/v3/ticker/24hr?symbol=${symbol}`);
                currentPrice = parseFloat(response.data.lastPrice);
                change24h = parseFloat(response.data.priceChangePercent);
                volume = parseFloat(response.data.quoteVolume);
            } else {
                currentPrice = 100 + Math.random() * 900;
                change24h = (Math.random() - 0.5) * 3;
                volume = 1000000 + Math.random() * 10000000;
            }
        } catch (e) {
            currentPrice = 50000 + Math.random() * 20000;
            change24h = (Math.random() - 0.5) * 5;
            volume = 10000000;
        }
        
        const volatility = Math.abs(change24h);
        const analysis = analyzeMarket(symbol, currentPrice, change24h, volume, volatility);
        const side = analysis.decision;
        
        // Deduct investment amount from balance
        user.balance = user.balance - amount;
        await user.save();
        
        const trade = new Trade({
            userId: user._id,
            symbol,
            symbolName,
            category,
            side,
            amount,
            leverage,
            duration,
            durationMs,
            entryPrice: currentPrice,
            analysis: analysis.reasons.join(' | '),
            aiPasskey: passkey,
            status: 'active'
        });
        
        await trade.save();
        
        res.json({
            success: true,
            trade: trade,
            analysis: {
                decision: side,
                confidence: analysis.confidence,
                reasons: analysis.reasons,
                signals: analysis.signals,
                entryPrice: currentPrice
            }
        });
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to start AI trade' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const activeTrades = await Trade.find({ userId: req.user.id, status: 'active' }).sort({ startedAt: -1 });
        const tradeHistory = await Trade.find({ userId: req.user.id, status: 'completed' }).sort({ endedAt: -1 }).limit(50);
        
        const totalInvested = tradeHistory.reduce((sum, t) => sum + t.amount, 0);
        const totalProfit = tradeHistory.reduce((sum, t) => sum + (t.profit || 0), 0);
        const roi = totalInvested > 0 ? (totalProfit / totalInvested) * 100 : 0;
        
        res.json({
            user,
            activeTrades,
            tradeHistory,
            roi: roi.toFixed(2)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.post('/api/ai/stop-trade/:tradeId', authenticateToken, async (req, res) => {
    try {
        const trade = await Trade.findOne({ _id: req.params.tradeId, userId: req.user.id, status: 'active' });
        if (!trade) {
            return res.status(404).json({ error: 'Active trade not found' });
        }
        
        trade.status = 'stopped';
        trade.endedAt = new Date();
        
        let profit = trade.profit || 0;
        
        if (profit < -10) {
            profit = -10;
            trade.profit = profit;
        }
        
        const user = await User.findById(req.user.id);
        if (user) {
            const amountToReturn = trade.amount + profit;
            user.balance = user.balance + amountToReturn;
            
            if (profit > 0) {
                user.totalProfit = (user.totalProfit || 0) + profit;
            } else {
                user.totalLoss = (user.totalLoss || 0) + Math.abs(profit);
            }
            await user.save();
        }
        
        await trade.save();
        
        res.json({ success: true, profit: profit });
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop trade' });
    }
});

// ============= DEPOSIT ROUTES (Minimum $60) =============
app.post('/api/deposit/create', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.user.id);
        
        // Minimum deposit $60
        if (amount < 60) {
            return res.status(400).json({ error: 'Minimum deposit is $60 USD' });
        }
        
        const paymentId = 'DEP_' + Date.now() + '_' + Math.random().toString(36).substr(2, 8);
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'deposit',
            amount: amount,
            status: 'pending',
            transactionId: paymentId,
            description: 'Crypto deposit'
        });
        await transaction.save();
        
        res.json({
            success: true,
            paymentId: paymentId
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create deposit' });
    }
});

app.get('/api/deposit/check/:paymentId', authenticateToken, async (req, res) => {
    try {
        const transaction = await Transaction.findOne({ transactionId: req.params.paymentId });
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }
        
        if (transaction.status === 'pending') {
            const elapsed = Date.now() - new Date(transaction.createdAt).getTime();
            if (elapsed > 10000) {
                transaction.status = 'completed';
                await transaction.save();
                
                const user = await User.findById(transaction.userId);
                if (user) {
                    user.balance = user.balance + transaction.amount;
                    user.totalDeposits = (user.totalDeposits || 0) + transaction.amount;
                    await user.save();
                }
            }
        }
        
        res.json({ status: transaction.status });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check status' });
    }
});

// ============= WITHDRAWAL ROUTES (2% fee) =============
app.post('/api/withdrawal/request', authenticateToken, async (req, res) => {
    try {
        const { amount, network, address } = req.body;
        const user = await User.findById(req.user.id);
        
        if (amount < 50) {
            return res.status(400).json({ error: 'Minimum withdrawal is $50' });
        }
        
        // Calculate 2% fee
        const feeAmount = amount * 0.02;
        const netAmount = amount - feeAmount;
        
        if (amount > user.balance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        user.balance = user.balance - amount;
        await user.save();
        
        const withdrawal = new Withdrawal({
            userId: user._id,
            userName: user.fullName,
            amount: amount,
            feeAmount: feeAmount,
            network: network,
            walletAddress: address,
            status: 'pending'
        });
        await withdrawal.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'withdrawal',
            amount: amount,
            withdrawalFee: feeAmount,
            transactionId: 'WD_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
            description: `Withdrawal request to ${network} address: ${address.substring(0, 10)}... (2% fee: $${feeAmount.toFixed(2)})`,
            status: 'pending'
        });
        await transaction.save();
        
        res.json({ success: true, message: 'Withdrawal request submitted', feeAmount: feeAmount, netAmount: netAmount });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// ============= ADMIN ROUTES =============
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/users/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });
        const transactions = await Transaction.find({ userId: req.params.userId }).sort({ createdAt: -1 }).limit(20);
        res.json({ user, transactions });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

app.post('/api/admin/add-balance', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, amount, description } = req.body;
        const admin = await User.findById(req.user.id);
        
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.balance = user.balance + amount;
        user.totalDeposits = (user.totalDeposits || 0) + amount;
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'admin_deposit',
            amount: amount,
            transactionId: 'ADMIN_DEP_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
            description: description || 'Admin deposit',
            adminName: admin.fullName
        });
        await transaction.save();
        
        res.json({ success: true, newBalance: user.balance, message: `Added $${amount} to ${user.fullName}` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add balance' });
    }
});

app.post('/api/admin/deduct-balance', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, amount, description } = req.body;
        const admin = await User.findById(req.user.id);
        
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
        
        user.balance = user.balance - amount;
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'admin_deduct',
            amount: amount,
            transactionId: 'ADMIN_WD_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
            description: description || 'Admin deduction',
            adminName: admin.fullName
        });
        await transaction.save();
        
        res.json({ success: true, newBalance: user.balance, message: `Deducted $${amount} from ${user.fullName}` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to deduct balance' });
    }
});

app.put('/api/admin/users/:userId/toggle-status', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.isActive = !user.isActive;
        await user.save();
        
        res.json({ success: true, isActive: user.isActive, message: `User ${user.isActive ? 'activated' : 'deactivated'}` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

app.get('/api/admin/transactions', authenticateToken, isAdmin, async (req, res) => {
    try {
        const transactions = await Transaction.find().sort({ createdAt: -1 }).limit(100);
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
        const totalProfit = await User.aggregate([{ $group: { _id: null, total: { $sum: '$totalProfit' } } }]);
        
        res.json({
            totalUsers,
            activeUsers,
            totalBalance: totalBalance[0]?.total || 0,
            totalProfit: totalProfit[0]?.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find().sort({ createdAt: -1 });
        res.json(withdrawals);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

app.post('/api/admin/withdrawals/:withdrawalId/process', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.withdrawalId);
        
        if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
        
        withdrawal.status = status;
        withdrawal.processedAt = new Date();
        withdrawal.processedBy = req.user.email;
        
        await withdrawal.save();
        
        await Transaction.findOneAndUpdate(
            { transactionId: { $regex: withdrawal._id } },
            { status: status === 'approved' ? 'completed' : 'failed' }
        );
        
        if (status === 'rejected') {
            const user = await User.findById(withdrawal.userId);
            if (user) {
                user.balance = user.balance + withdrawal.amount;
                await user.save();
            }
        }
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// Create default admin
async function createDefaultAdmin() {
    const adminExists = await User.findOne({ email: 'admin@algonflow.com' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('Admin123!', 10);
        const admin = new User({
            email: 'admin@algonflow.com',
            password: hashedPassword,
            fullName: 'System Administrator',
            age: 30,
            country: 'United States',
            countryCode: '+1',
            phoneNumber: '1234567890',
            employmentStatus: 'Employed',
            tradingExperience: 'Expert',
            fundsSource: 'Business Revenue',
            termsAccepted: true,
            isAdmin: true,
            balance: 10000,
            aiApiKey: 'ADMIN2024KEY'
        });
        await admin.save();
        console.log('✅ Default admin created: admin@algonflow.com / Admin123!');
    }
}

// Serve HTML files (optional - if you want to serve from Render)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/profile.html', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/deposit', (req, res) => res.sendFile(path.join(__dirname, 'deposit.html')));
app.get('/deposit.html', (req, res) => res.sendFile(path.join(__dirname, 'deposit.html')));
app.get('/withdraw', (req, res) => res.sendFile(path.join(__dirname, 'withdraw.html')));
app.get('/withdraw.html', (req, res) => res.sendFile(path.join(__dirname, 'withdraw.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, async () => {
    await createDefaultAdmin();
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ CORS enabled for all origins - frontend can be hosted anywhere!`);
    console.log(`📱 Backend API available at: https://algon-flow-market.onrender.com`);
});