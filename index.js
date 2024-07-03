    const express = require('express');
    const session = require('express-session');
    const bodyParser = require('body-parser');
    const bcrypt = require('bcryptjs');
    const { Client , MessageMedia} = require('whatsapp-web.js');
    const qrcode = require('qrcode');
    const fs = require('fs');
    const app = express();
    const PORT = process.env.PORT || 3000;
    const puppeteer =require('puppeteer');

    // In-memory user database (for simplicity)

    // In-memory store for WhatsApp clients
    const clients = {};

    // Configure session middleware
    app.use(session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: false
    }));

    app.use(bodyParser.json({ limit: '50mb' }));
    app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
    app.use(express.static('public'));

    function readDatabase() {
        const data = fs.readFileSync('database.json');
        return JSON.parse(data);
    }

    // Function to write data to JSON file
    function writeDatabase(data) {
        fs.writeFileSync('database.json', JSON.stringify(data, null, 2));
    }

    // Middleware to check if user is authenticated
    function isAuthenticated(req, res, next) {
        if (req.session.userId) {
            return next();
        }
        res.status(401).send('You need to log in first.');
    }

    function getUserById(userId) {
        const database = readDatabase();
        return database.users.find(user => user.username === userId);
    }
    app.get('/is-logged-in', (req, res) => {
        if (req.session.userId) {
            res.json({ loggedIn: true });
        } else {
            res.json({ loggedIn: false });
        }
    });
    // Endpoint for user login
    app.post('/login', async (req, res) => {
        console.log("loginnn")
        const { username, password } = req.body;
        //const user = users.find(u => u.username === username);
        const user1 = getUserById(username);
        //console.log(password,user1.password)
        //console.log(await bcrypt.compare(password, user1.password))

        if (user1 && await bcrypt.compare(password, user1.password)) {
            req.session.userId = user1.id;
            req.session.phone = user1.phone;
            req.session.username = user1.username;
            res.json({ message: 'Login successful' });
            
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    });

    app.post('/logout', (req, res) => {          
            //console.log("DELETE"+req.session.clientId);
            if(req.session.clientId){            
            delete clients[req.session.clientId];            
            }
            req.session.destroy();
            res.json({ message: 'Logged out' });
    });

    // Endpoint to get QR code for login
    app.get('/qr', isAuthenticated, (req, res) => {
        if (!req.session.clientId) {
            const clientId = Date.now().toString(); // Generate a unique client ID
            const client = new Client({
                puppeteer: {
                headless: true,
                executablePath: '/usr/bin/google-chrome',
                args: ['--no-sandbox', '--disable-gpu', '--disable-setuid-sandbox'],
            },
                webVersionCache: {
                type: "remote",
                remotePath:
                    "https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2411.2.html",
                },
                authTimeoutMs: 60000, // Optional: timeout for authentication in milliseconds
                qrTimeout: 30000, // Optional: timeout for QR code generation
            });
            clients[clientId] = client;

            client.on('qr', (qr) => {
                qrcode.toDataURL(qr, (err, url) => {
                    req.session.qrCode = url;
                    req.session.clientId = clientId;
                    req.session.clientReady = false;
                    req.session.save();
                    res.json({ qr: url });
                });
            });

            client.on('ready', () => {
                req.session.clientReady = true;
                req.session.save();
                console.log('Client is ready!');

            });

            client.on('authenticated', () => {
                console.log('Client authenticated!');
            });

            client.on('auth_failure', (msg) => {
                console.error('AUTHENTICATION FAILURE', msg);
                req.session.destroy();
                delete clients[clientId];
            });

            client.on('disconnected', (reason) => {
                console.log('Client was logged out', reason);
                req.session.destroy();
                delete clients[clientId];
            });
            client.initialize();
        } else if (req.session.qrCode && !req.session.clientReady) {
            res.json({ qr: req.session.qrCode });
        } else {
            res.json({ message: 'Already authenticated' });
        }
    });

    app.get('/status', isAuthenticated, (req, res) => {
        if (req.session.clientReady) {
            console.log(req.session.clientReady+"niubioo");
            res.json({ ready: true });
        } else {
            res.json({ ready: false });
        }
    });

    app.post('/match', isAuthenticated, (req, res) => {
        const { number, message } = req.body;
        const client = clients[req.session.clientId];
        console.log(client.info.wid.user!=req.session.phone);
        if(client.info.wid.user!=req.session.phone){
            console.log('Client was logged out');
            res.json({ message: 'Phone number doesnt match our record' });
            delete clients[req.session.clientId];
        }else{
            res.json({ message: 'success' });
        }
    });
    // Endpoint to send a message
    app.post('/send-message', isAuthenticated, (req, res) => {
        const { number, message } = req.body;
        const client = clients[req.session.clientId];
        console.log(client.info.wid.user,req.session.phone);
        if(client.info.wid.user!=req.session.phone){
            console.log("DESTROY!");
        req.session.destroy();
        delete clients[client];
        res.status(500).json({ error: "User phone not same as recorded. Logging out..." });
    }else{
        console.log("YESYES");

        client.sendMessage(`${number}@c.us`, message)
            .then(response => {
                res.json({ status: 'Message sent', response });
            })
            .catch(err => {
                res.status(500).json({ error: err.message });
            });
        }
    });


    app.post('/send-pic',isAuthenticated,async (req, res) => {
    const { phoneNumber, photoFile } = req.body;
    let formattedNumber = phoneNumber.includes('@c.us') ? phoneNumber : `${phoneNumber}@c.us`;

    const client = clients[req.session.clientId];
    console.log(client.info.wid.user!=req.session.phone);
    if(client.info.wid.user!=req.session.phone){
        console.log("DESTROY!");
    req.session.destroy();
    delete clients[client];
    res.status(500).json({ error: "User phone not same as recorded. Logging out..." });
    }else{
    console.log("YESYES");

    const media = new MessageMedia('image/png', photoFile.substring(22));
    await client.sendMessage(formattedNumber, media)
        .then(response => {
            res.json({ status: 'Message sent', response });
        })
        .catch(err => {
            res.status(500).json({ error: err.message });
        });
    }

    });

    app.post('/change-password', async (req, res) => {
        const { oldPassword, newPassword } = req.body;
        const userId = req.session.username;
        console.log(req.session)
        const user = getUserById(userId);
        const database = readDatabase();

        if (!user) {
            return res.status(401).json({ status: 'error', message: 'Unauthorized' });
        }
        console.log(bcrypt.compare(oldPassword, user.password))
        console.log(newPassword, user.password)

        if (bcrypt.compare(oldPassword, user.password)==false) {
            return res.status(400).json({ status: 'error', message: 'Incorrect old password' });
        }
        const saltRounds = 10;
        var newHash = "";
        console.log("1234567890"+database.users.findIndex(user => user.username === userId));

        await bcrypt.hash(newPassword, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            database.users.forEach(function (Student) {
                if (Student.id == user.id) {
                    Student.password = hash
                    writeDatabase(database);
                }
            });
        // database.users[database.users.findIndex(user => user.username === userId)].password = hash;
            //newHash = hash;
            console.log(hash)
        });

        res.json({ status: 'success', message: 'Password changed successfully' });
    });


    // Serve login page
    app.get('/login', (req, res) => {
        res.sendFile(__dirname + '/public/login.html');
    });

    // Start Express server
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
