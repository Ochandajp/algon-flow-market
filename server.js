require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Session store with MongoDB (production ready)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://officialwrittershub_db_user:Fellix@cluster0.6g8mg9p.mongodb.net/algonflow?retryWrites=true&w=majority';

app.use(session({
    secret: process.env.SESSION_SECRET || 'algonflow_secret_key_2024',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        ttl: 24 * 60 * 60 // 1 day
    }),
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// MongoDB Connection (without deprecated options)
mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
}).then(() => console.log('✅ Connected to MongoDB'))
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
    winningTrades: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    isAdmin: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    isVerified: { type: Boolean, default: false },
    withdrawalAddress: { type: String, default: '' },
    termsAccepted: { type: Boolean, required: true },
    termsAcceptedAt: { type: Date },
    tradesHistory: { type: Array, default: [] },
    aiApiKey: { type: String, default: '' },
    pendingWithdrawals: { type: Array, default: [] }
});

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'profit', 'trade'], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    transactionId: { type: String, unique: true },
    description: { type: String },
    network: { type: String },
    address: { type: String },
    createdAt: { type: Date, default: Date.now },
    approvedAt: { type: Date }
});

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    amount: { type: Number, required: true },
    paymentId: { type: String, unique: true },
    status: { type: String, enum: ['pending', 'confirmed', 'failed'], default: 'pending' },
    paymentMethod: { type: String, default: 'crypto' },
    createdAt: { type: Date, default: Date.now },
    confirmedAt: { type: Date }
});

const aiTradeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    symbol: { type: String, required: true },
    symbolName: { type: String, required: true },
    category: { type: String, required: true },
    amount: { type: Number, required: true },
    leverage: { type: Number, default: 1 },
    duration: { type: String, required: true },
    durationMs: { type: Number, required: true },
    side: { type: String, enum: ['buy', 'sell'] },
    status: { type: String, enum: ['active', 'completed', 'stopped', 'loss'], default: 'active' },
    entryPrice: { type: Number },
    currentPrice: { type: Number },
    profit: { type: Number, default: 0 },
    profitPercent: { type: Number, default: 0 },
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date },
    aiApiKey: { type: String },
    tradeHistory: { type: Array, default: [] }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const AITrade = mongoose.model('AITrade', aiTradeSchema);

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

// ============= AUTH ROUTES =============
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, fullName, age, country, countryCode, phoneNumber, employmentStatus, tradingExperience, fundsSource, termsAccepted } = req.body;
        
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
            balance: 0,
            isVerified: false,
            isAdmin: email === 'admin@algonflow.com'
        });
        
        await user.save();
        
        const token = jwt.sign({ id: user._id, email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'algonflow_jwt_secret');
        
        res.status(201).json({ 
            success: true, 
            token, 
            user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin, isVerified: user.isVerified }
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
            user: { id: user._id, email: user.email, fullName: user.fullName, balance: user.balance, isAdmin: user.isAdmin, isVerified: user.isVerified }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// ============= DEPOSIT ROUTES =============
app.post('/api/deposit/create', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.user.id);
        
        const MIN_DEPOSIT = parseInt(process.env.MIN_DEPOSIT) || 80;
        if (amount < MIN_DEPOSIT) {
            return res.status(400).json({ error: `Minimum deposit is $${MIN_DEPOSIT} USD` });
        }
        
        const paymentId = 'DEP_' + Date.now() + '_' + Math.random().toString(36).substr(2, 8);
        
        const deposit = new Deposit({
            userId: user._id,
            userName: user.fullName,
            amount: amount,
            paymentId: paymentId,
            status: 'pending'
        });
        
        await deposit.save();
        
        const nowPaymentsUrl = `https://nowpayments.io/donation?api_key=${process.env.NOWPAYMENTS_API_KEY}&amount=${amount}&currency=USD`;
        
        res.json({ 
            success: true, 
            paymentId: paymentId,
            nowPaymentsUrl: nowPaymentsUrl,
            deposit: deposit
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create deposit' });
    }
});

app.post('/api/deposit/confirm-webhook', async (req, res) => {
    try {
        const { paymentId, status, amount } = req.body;
        
        const deposit = await Deposit.findOne({ paymentId: paymentId });
        if (!deposit) return res.status(404).json({ error: 'Deposit not found' });
        
        if (status === 'confirmed') {
            deposit.status = 'confirmed';
            deposit.confirmedAt = new Date();
            await deposit.save();
            
            const user = await User.findById(deposit.userId);
            user.balance += deposit.amount;
            user.totalDeposits += deposit.amount;
            
            await user.save();
            
            const transaction = new Transaction({
                userId: user._id,
                userName: user.fullName,
                type: 'deposit',
                amount: deposit.amount,
                status: 'completed',
                transactionId: 'TXN_' + Date.now(),
                description: 'Deposit via NowPayments'
            });
            await transaction.save();
        }
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

app.get('/api/deposit/check/:paymentId', authenticateToken, async (req, res) => {
    try {
        const deposit = await Deposit.findOne({ paymentId: req.params.paymentId });
        if (!deposit) return res.status(404).json({ error: 'Deposit not found' });
        
        res.json({ status: deposit.status, deposit: deposit });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check deposit' });
    }
});

// ============= WITHDRAWAL ROUTES =============
app.post('/api/withdrawal/request', authenticateToken, async (req, res) => {
    try {
        const { amount, network, address } = req.body;
        const user = await User.findById(req.user.id);
        
        const MIN_WITHDRAWAL = parseInt(process.env.MIN_WITHDRAWAL) || 50;
        if (amount < MIN_WITHDRAWAL) {
            return res.status(400).json({ error: `Minimum withdrawal is $${MIN_WITHDRAWAL} USD` });
        }
        
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        const withdrawalId = 'WD_' + Date.now() + '_' + Math.random().toString(36).substr(2, 8);
        
        user.balance -= amount;
        
        user.pendingWithdrawals.push({
            id: withdrawalId,
            amount: amount,
            network: network,
            address: address,
            status: 'pending',
            requestedAt: new Date()
        });
        
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'withdrawal',
            amount: amount,
            status: 'pending',
            transactionId: withdrawalId,
            network: network,
            address: address,
            description: `Withdrawal request to ${network}`
        });
        await transaction.save();
        
        res.json({ success: true, withdrawalId: withdrawalId, newBalance: user.balance });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal' });
    }
});

// ============= AI TRADING ROUTES =============
app.post('/api/ai/save-passkey', authenticateToken, async (req, res) => {
    try {
        const { passkey } = req.body;
        const user = await User.findById(req.user.id);
        
        user.aiApiKey = passkey;
        await user.save();
        
        res.json({ success: true, message: 'Passkey saved successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save passkey' });
    }
});

// Calculate profit based on amount and duration (Loss below 12%)
function calculateProfit(amount, durationMs, side) {
    const amountInUSD = amount;
    let profitPercent = 0;
    
    const AI_PROFIT_SMALL = parseInt(process.env.AI_PROFIT_SMALL) || 25;
    const AI_PROFIT_MEDIUM = parseInt(process.env.AI_PROFIT_MEDIUM) || 70;
    const AI_PROFIT_LARGE = parseInt(process.env.AI_PROFIT_LARGE) || 83;
    const MAX_LOSS_PERCENT = parseFloat(process.env.MAX_LOSS_PERCENT) || 11.9;
    const COMPANY_FEE_PERCENT = parseFloat(process.env.COMPANY_FEE_PERCENT) || 3;
    
    if (amountInUSD < 500) {
        profitPercent = AI_PROFIT_SMALL;
    } else if (amountInUSD >= 500 && amountInUSD < 3000) {
        profitPercent = AI_PROFIT_MEDIUM;
    } else {
        profitPercent = AI_PROFIT_LARGE;
    }
    
    const durationHours = durationMs / (1000 * 60 * 60);
    if (durationHours < 0.1) {
        profitPercent = profitPercent * 0.3;
    } else if (durationHours < 1) {
        profitPercent = profitPercent * 0.5;
    } else if (durationHours >= 24) {
        profitPercent = profitPercent * 1.2;
    }
    
    // Loss rate below MAX_LOSS_PERCENT (default 11.9%)
    const isLoss = Math.random() < 0.3;
    
    if (isLoss) {
        profitPercent = -(Math.random() * MAX_LOSS_PERCENT);
    }
    
    const grossProfit = (amount * profitPercent) / 100;
    const companyFee = grossProfit * (COMPANY_FEE_PERCENT / 100);
    const netProfit = grossProfit - companyFee;
    
    return {
        profitPercent: profitPercent,
        grossProfit: grossProfit,
        companyFee: companyFee,
        netProfit: netProfit,
        isLoss: isLoss
    };
}

// Analyze market and decide side
async function analyzeMarket(symbol, category, passkey) {
    const volatility = Math.random() * 100;
    const momentum = Math.random() * 200 - 100;
    const rsi = Math.random() * 100;
    const macd = Math.random() * 2 - 1;
    
    let decision = 'buy';
    let confidence = 50;
    
    if (momentum > 50 && rsi < 70) {
        decision = 'buy';
        confidence = 70 + Math.random() * 20;
    } else if (momentum < -50 && rsi > 30) {
        decision = 'sell';
        confidence = 70 + Math.random() * 20;
    } else {
        decision = Math.random() > 0.5 ? 'buy' : 'sell';
        confidence = 50 + Math.random() * 30;
    }
    
    return {
        side: decision,
        confidence: confidence,
        volatility: volatility,
        momentum: momentum,
        rsi: rsi,
        macd: macd,
        analysis: `AI Analysis: ${decision.toUpperCase()} signal with ${confidence.toFixed(1)}% confidence. Volatility: ${volatility.toFixed(1)}%, Momentum: ${momentum.toFixed(1)}`
    };
}

app.post('/api/ai/start-trade', authenticateToken, async (req, res) => {
    try {
        const { symbol, symbolName, category, amount, leverage, duration, durationMs, passkey } = req.body;
        const user = await User.findById(req.user.id);
        
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        if (user.aiApiKey !== passkey && passkey) {
            user.aiApiKey = passkey;
            await user.save();
        }
        
        user.balance -= amount;
        await user.save();
        
        const analysis = await analyzeMarket(symbol, category, passkey);
        const profitCalc = calculateProfit(amount, durationMs, analysis.side);
        
        let currentPrice = 0;
        try {
            const priceResponse = await axios.get(`https://api.binance.com/api/v3/ticker/price?symbol=${symbol}USDT`);
            currentPrice = parseFloat(priceResponse.data.price);
        } catch (e) {
            currentPrice = 100 + Math.random() * 900;
        }
        
        const trade = new AITrade({
            userId: user._id,
            userName: user.fullName,
            symbol: symbol,
            symbolName: symbolName,
            category: category,
            amount: amount,
            leverage: leverage,
            duration: duration,
            durationMs: durationMs,
            side: analysis.side,
            status: 'active',
            entryPrice: currentPrice,
            currentPrice: currentPrice,
            aiApiKey: passkey || user.aiApiKey,
            tradeHistory: [{
                timestamp: new Date(),
                action: 'started',
                analysis: analysis.analysis,
                price: currentPrice
            }]
        });
        
        await trade.save();
        
        setTimeout(async () => {
            await completeTrade(trade._id);
        }, durationMs);
        
        res.json({
            success: true,
            trade: trade,
            analysis: analysis,
            projectedProfit: profitCalc
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to start AI trade' });
    }
});

async function completeTrade(tradeId) {
    try {
        const trade = await AITrade.findById(tradeId);
        if (!trade || trade.status !== 'active') return;
        
        const user = await User.findById(trade.userId);
        if (!user) return;
        
        let finalPrice = trade.entryPrice;
        try {
            const priceResponse = await axios.get(`https://api.binance.com/api/v3/ticker/price?symbol=${trade.symbol}USDT`);
            finalPrice = parseFloat(priceResponse.data.price);
        } catch (e) {
            const priceChange = (Math.random() - 0.5) * 0.2;
            finalPrice = trade.entryPrice * (1 + priceChange);
        }
        
        trade.currentPrice = finalPrice;
        
        const priceChangePercent = ((finalPrice - trade.entryPrice) / trade.entryPrice) * 100;
        const sideMultiplier = trade.side === 'buy' ? 1 : -1;
        const actualPriceProfitPercent = priceChangePercent * sideMultiplier;
        
        const profitCalc = calculateProfit(trade.amount, trade.durationMs, trade.side);
        
        let finalProfit = profitCalc.netProfit;
        let finalProfitPercent = profitCalc.profitPercent;
        let isLoss = profitCalc.isLoss;
        
        const marketImpact = actualPriceProfitPercent / 10;
        finalProfit = finalProfit * (1 + marketImpact);
        finalProfitPercent = finalProfitPercent * (1 + marketImpact);
        
        const MAX_LOSS_PERCENT = parseFloat(process.env.MAX_LOSS_PERCENT) || 11.9;
        if (finalProfit < 0) {
            isLoss = true;
            finalProfit = Math.max(finalProfit, -trade.amount * (MAX_LOSS_PERCENT / 100));
            finalProfitPercent = (finalProfit / trade.amount) * 100;
        }
        
        trade.profit = finalProfit;
        trade.profitPercent = finalProfitPercent;
        trade.status = isLoss ? 'loss' : 'completed';
        trade.endedAt = new Date();
        trade.tradeHistory.push({
            timestamp: new Date(),
            action: 'completed',
            price: finalPrice,
            profit: finalProfit,
            profitPercent: finalProfitPercent
        });
        
        await trade.save();
        
        const amountToReturn = trade.amount + finalProfit;
        user.balance += amountToReturn;
        
        if (finalProfit > 0) {
            user.totalProfit += finalProfit;
            user.winningTrades += 1;
        } else {
            user.totalLoss += Math.abs(finalProfit);
        }
        
        user.totalTrades += 1;
        user.winRate = (user.winningTrades / user.totalTrades) * 100;
        
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'trade',
            amount: finalProfit,
            status: 'completed',
            transactionId: 'TRADE_' + tradeId,
            description: `${trade.side.toUpperCase()} ${trade.symbolName} - ${trade.duration} - ${finalProfit > 0 ? 'Profit' : 'Loss'}: $${Math.abs(finalProfit).toFixed(2)}`
        });
        await transaction.save();
        
    } catch (error) {
        console.error('Error completing trade:', error);
    }
}

app.get('/api/ai/active-trades', authenticateToken, async (req, res) => {
    try {
        const trades = await AITrade.find({ 
            userId: req.user.id, 
            status: 'active' 
        }).sort({ startedAt: -1 });
        
        res.json(trades);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch active trades' });
    }
});

app.get('/api/ai/trade-history', authenticateToken, async (req, res) => {
    try {
        const trades = await AITrade.find({ 
            userId: req.user.id, 
            status: { $in: ['completed', 'loss'] }
        }).sort({ endedAt: -1 }).limit(50);
        
        res.json(trades);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch trade history' });
    }
});

app.post('/api/ai/stop-trade/:tradeId', authenticateToken, async (req, res) => {
    try {
        const trade = await AITrade.findOne({ _id: req.params.tradeId, userId: req.user.id });
        if (!trade) return res.status(404).json({ error: 'Trade not found' });
        
        if (trade.status !== 'active') {
            return res.status(400).json({ error: 'Trade is already completed' });
        }
        
        await completeTrade(trade._id);
        
        res.json({ success: true, message: 'Trade stopped successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop trade' });
    }
});

// ============= USER PROFILE ROUTES =============
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const transactions = await Transaction.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(50);
        const activeTrades = await AITrade.find({ userId: req.user.id, status: 'active' });
        const tradeHistory = await AITrade.find({ userId: req.user.id, status: { $in: ['completed', 'loss'] } }).sort({ endedAt: -1 }).limit(20);
        
        const roi = user.totalDeposits > 0 ? ((user.totalProfit - user.totalLoss) / user.totalDeposits * 100) : 0;
        
        res.json({ 
            user, 
            transactions, 
            activeTrades, 
            tradeHistory,
            roi: roi.toFixed(2)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
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

app.post('/api/admin/add-balance', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, amount, description } = req.body;
        
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.balance += amount;
        user.totalDeposits += amount;
        
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'deposit',
            amount: amount,
            status: 'completed',
            transactionId: 'ADMIN_DEP_' + Date.now(),
            description: description || 'Admin deposit'
        });
        await transaction.save();
        
        res.json({ success: true, newBalance: user.balance });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add balance' });
    }
});

app.post('/api/admin/deduct-balance', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, amount, description } = req.body;
        
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
        
        user.balance -= amount;
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'withdrawal',
            amount: amount,
            status: 'completed',
            transactionId: 'ADMIN_WD_' + Date.now(),
            description: description || 'Admin deduction'
        });
        await transaction.save();
        
        res.json({ success: true, newBalance: user.balance });
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
        
        res.json({ success: true, isActive: user.isActive });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

app.put('/api/admin/users/:userId/verify', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        user.isVerified = !user.isVerified;
        await user.save();
        
        res.json({ success: true, isVerified: user.isVerified });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update verification status' });
    }
});

app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({ 'pendingWithdrawals.0': { $exists: true } });
        const allWithdrawals = [];
        
        for (const user of users) {
            for (const wd of user.pendingWithdrawals) {
                if (wd.status === 'pending') {
                    allWithdrawals.push({
                        id: wd.id,
                        userId: user._id,
                        userName: user.fullName,
                        email: user.email,
                        amount: wd.amount,
                        network: wd.network,
                        address: wd.address,
                        requestedAt: wd.requestedAt
                    });
                }
            }
        }
        
        res.json(allWithdrawals);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

app.post('/api/admin/approve-withdrawal', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { withdrawalId } = req.body;
        
        const user = await User.findOne({ 'pendingWithdrawals.id': withdrawalId });
        if (!user) return res.status(404).json({ error: 'Withdrawal not found' });
        
        const withdrawal = user.pendingWithdrawals.find(w => w.id === withdrawalId);
        if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
        
        withdrawal.status = 'approved';
        withdrawal.approvedAt = new Date();
        
        await user.save();
        
        await Transaction.findOneAndUpdate(
            { transactionId: withdrawalId },
            { status: 'completed', approvedAt: new Date() }
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve withdrawal' });
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

app.get('/api/admin/deposits', authenticateToken, isAdmin, async (req, res) => {
    try {
        const deposits = await Deposit.find().sort({ createdAt: -1 });
        res.json(deposits);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch deposits' });
    }
});

app.post('/api/admin/confirm-deposit', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { depositId } = req.body;
        
        const deposit = await Deposit.findById(depositId);
        if (!deposit) return res.status(404).json({ error: 'Deposit not found' });
        
        if (deposit.status === 'confirmed') {
            return res.status(400).json({ error: 'Deposit already confirmed' });
        }
        
        deposit.status = 'confirmed';
        deposit.confirmedAt = new Date();
        await deposit.save();
        
        const user = await User.findById(deposit.userId);
        user.balance += deposit.amount;
        user.totalDeposits += deposit.amount;
        
        await user.save();
        
        const transaction = new Transaction({
            userId: user._id,
            userName: user.fullName,
            type: 'deposit',
            amount: deposit.amount,
            status: 'completed',
            transactionId: 'DEP_' + deposit.paymentId,
            description: 'Deposit confirmed by admin'
        });
        await transaction.save();
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to confirm deposit' });
    }
});

// ============= MARKET DATA API =============
app.get('/api/market/price/:symbol', async (req, res) => {
    try {
        const symbol = req.params.symbol.toUpperCase();
        const response = await axios.get(`https://api.binance.com/api/v3/ticker/24hr?symbol=${symbol}USDT`);
        res.json({
            symbol: symbol,
            price: parseFloat(response.data.lastPrice),
            change: parseFloat(response.data.priceChangePercent),
            high: parseFloat(response.data.highPrice),
            low: parseFloat(response.data.lowPrice),
            volume: parseFloat(response.data.volume)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch price' });
    }
});

app.get('/api/market/candles/:symbol', async (req, res) => {
    try {
        const symbol = req.params.symbol.toUpperCase();
        const interval = req.query.interval || '1h';
        const limit = req.query.limit || 100;
        
        const response = await axios.get(`https://api.binance.com/api/v3/klines`, {
            params: { symbol: `${symbol}USDT`, interval: interval, limit: limit }
        });
        
        const candles = response.data.map(candle => ({
            time: candle[0],
            open: parseFloat(candle[1]),
            high: parseFloat(candle[2]),
            low: parseFloat(candle[3]),
            close: parseFloat(candle[4]),
            volume: parseFloat(candle[5])
        }));
        
        res.json(candles);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch candles' });
    }
});

// Serve static pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/deposit.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'deposit.html'));
});

app.get('/withdraw.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'withdraw.html'));
});

app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
});

// Create default admin if not exists
async function createDefaultAdmin() {
    const adminExists = await User.findOne({ email: process.env.ADMIN_EMAIL || 'admin@algonflow.com' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin123!', 10);
        const admin = new User({
            email: process.env.ADMIN_EMAIL || 'admin@algonflow.com',
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
            isVerified: true,
            balance: 0
        });
        await admin.save();
        console.log('✅ Default admin created:', process.env.ADMIN_EMAIL || 'admin@algonflow.com');
    }
}

app.listen(PORT, '0.0.0.0', async () => {
    await createDefaultAdmin();
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});