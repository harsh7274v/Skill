const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const flash = require('connect-flash');
const cors=require("cors");
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');







const app = express();
const port = 3000;

// Connect to MongoDB
mongoose.connect('mongodb+srv://skillxstream:skillX123@mydb.herlvtw.mongodb.net/');

// Define schema
const userSchema = new mongoose.Schema({
    name: { required: true, type: String},
    email: { required: true, type: String, unique: true},
    confirmPassword: { required: true, type: String} 
});

// Define routes here

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(express.static(__dirname + '/public'));
app.use(express.static(__dirname + '/public/pages'));
app.use(express.static(__dirname + '/public/subjects'));
app.use(express.static(__dirname + '/public/assets/css'));
app.use(express.static(__dirname + '/views/dashbord.ejs'));
app.use(flash());
app.use(cors());
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
  secret: 'your secret key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set secure to true if you're using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});
  



app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/pages/login.html');
});
app.get('/api/services.html', (req, res) => {
    res.sendFile(__dirname + '/public/pages/services.html');
});
app.get('/api/subjects/computer_courses.html', (req, res) => {
    res.sendFile(__dirname + '/public/subjects/computer_courses.html');
});
app.get('/api/subjects/quiz.html', (req, res) => {
    res.sendFile(__dirname + '/public/subjects/quiz.html');
});

app.get('/about', (req, res) => {
    res.sendFile(__dirname + '/public/pages/about.html');
});

app.get('/contact', (req, res) => {
    res.sendFile(__dirname + '/public/pages/contact.html');
});
app.get('/api/subjects/index.html', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});
app.get("/logout",(req,res)=>{
    res.sendFile(__dirname+"/public/index.html");
})

app.get("/public/pages/courses.html",(req,res)=>{
    res.sendFile(__dirname+"/public/pages/courses.html");
})
app.get("/public/dashbord.html",(req,res)=>{
    res.sendFile(__dirname+"/public/dashbord.html");
})

app.get('/api/contact.html', (req, res) => {
    res.sendFile(__dirname + '/public/pages/contact.html');
});

const User = mongoose.model('User', userSchema);



app.post('/api/register', async (req, res, next) => {
    const { name, email, confirmPassword } = req.body;
    if (!confirmPassword) {
        return res.status(400).json({ message: 'Password is required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(confirmPassword, 10);
        const user = new User({ name, email, confirmPassword: hashedPassword });
        const savedUser = await user.save();

        // Authenticate the user after registration
        req.login(savedUser, (err) => {
            if (err) { return next(err); }
            // Redirect to the courses page after successful login
            return res.redirect('/public/pages/courses.html');
        });
    } catch (error) {
        if (error.name === 'MongoError' && error.code === 11000) {
            // Duplicate email
            return res.status(409).json({ message: 'Email already exists' });
        }
        res.status(500).json({ message: 'Error registering new user.' });
    }
});





app.post('/api/login', async (req, res, next) => {
    const { email, confirmPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }
    if (await bcrypt.compare(confirmPassword, user.confirmPassword)) {
        const token = jwt.sign({ email: user.email }, 'secret');
        res.cookie('token', token, { httpOnly: true }); // Set a cookie with the JWT

        // Manually establish the session
        req.logIn(user, function(err) {
            if (err) { return next(err); }
            return res.sendFile(__dirname + '/public/pages/courses.html');
        });
    } else {
        res.status(400).json({ message: 'Incorrect password' });
    }
});

const LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
    function(username, password, done) {
      User.findOne({ username: username }, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false, { message: 'Incorrect username.' }); }
        if (!bcrypt.compareSync(password, user.password)) { return done(null, false, { message: 'Incorrect password.' }); }
        return done(null, user);
      });
    }
  ));
  
passport.serializeUser(function(user, done) {
    done(null, user._id); // Use _id instead of id
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});


  




app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), async (req, res) => {
    // Fetch the user data
    const user = await User.findById(req.user.id);
    // Send the user data to the dashboard
    res.render('dashboard', { user: user });
});


  


app.get("/logout", (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        req.flash("success", "You are logged out!");
        res.redirect("/public/index.html");
    });
});
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('dashboard', { user: req.user });
  } else {
    res.redirect('/login');
  }
});


app.get('/api/user_data', (req, res) => {
    if (req.isAuthenticated()) {
        // Send user data as JSON
        res.json({
            name: req.user.name,
            email: req.user.email
        });
    } else {
        // If the user is not authenticated, send an error status
        res.status(401).json({ message: 'User not authenticated' });
    }
});


  
  
  
  




//for mail
let transporter = nodemailer.createTransport({
    service: 'gmail', // replace with your email service
    auth: {
        user: 'skillxstream@gmail.com', // replace with your email
        pass: 'holl' // replace with your password
    }
});

app.post('/contact', (req, res) => {
    const { name, email, message } = req.body;

    // Send email
    let mailOptions = {
        from: 'skillxstream@gmail.com', // replace with your email
        to: 'skillxstream+support@gmail.com', // replace with the email you want to send to
        subject: `New message from ${name}`,
        text: `You received a new message from ${name} (${email}):\n\n${message}`
    };
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            res.status(500).send('Error sending email');
        } else {
            console.log('Email sent: ' + info.response);
            res.status(200).send('Email sent');
        }
    });
});



app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
