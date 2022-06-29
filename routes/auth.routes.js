// routes/auth.routes.js

const { Router } = require("express");
const router = new Router();

const bcryptjs = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

router.get("/signup", (req, res) => res.render("auth/signup"));

router.post('/signup', (req, res, next) => {

    const { username, password } = req.body;

    if (!username || !password) {
        res.render('auth/signup', { errorMessage: 'Indicate username and password' });
        return;
      }

    bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(passwordEncripted => {
      console.log(`Password hash: ${passwordEncripted}`)
      User.create({
        username,
        password: passwordEncripted,
       
      })
    })
    .then(() => {
        res.redirect("/");
      })
      .catch(error => next(error))
    })

router.get('/login', (req, res) => res.render('auth/login'));

router.post('/login', (req, res, next) => {
    console.log("Session", req.session)

    const { username, password } = req.body;

    if (!username || !password) {
        res.render('auth/login', { errorMessage: 'Indicate username and password' });
        return;
      }
      User.findOne({ username })

      .then((user) => {
          if (!user) {
              res.render("auth/login", { errorMessage:'Username is not registered' })
              return;
          }
          else if (bcryptjs.compareSync(password, user.password)){
              req.session.currentUser = user;
              res.render('users/userProfile', {user});
          }
          else {
            res.render('auth/login', { errorMessage: 'Incorrect password.' });
          }
      })

      .catch(error => next(error));   
})

router.get("/main" , isLoggedIn, (req, res) => res.render('users/main',{ userInSession: req.session.currentUser } ))
router.get("/private" , isLoggedIn, (req, res) => res.render('users/private',{ userInSession: req.session.currentUser } ))

//router.get("/userProfile",isLoggedIn, (req, res) => res.render("users/userProfile",{ userInSession: req.session.currentUser } ))

  
    



module.exports = router