const express = require("express");
const router = express.Router();
const uid2 = require("uid2");
const encBase64 = require("crypto-js/enc-base64");
const SHA256 = require("crypto-js/sha256");

const User = require("../models/User");

router.post("/user/signup", async (req, res) => {
  try {
    const findExistingEmail = await User.findOne({ email: req.body.email });
    console.log(findExistingEmail);
    if (findExistingEmail) {
      return res.json("This email has already been saved in the database");
    }
    if (!req.body.username || !req.body.password || !req.body.email) {
      return res.json("Missing parameters !");
    }

    const password = req.body.password;
    // console.log(password);
    const salt = uid2(16);
    // console.log(salt);
    const hash = SHA256(password + salt).toString(encBase64);
    // console.log(hash);
    const token = uid2(64);
    // console.log(token);
    const newUser = new User({
      email: req.body.email,
      account: {
        username: req.body.username,
      },
      newsletter: req.body.newsletter,
      token: token,
      hash: hash,
      salt: salt,
    });
    await newUser.save();

    const newObj = {
      _id: newUser._id,
      token: newUser.token,
      account: {
        username: newUser.account.username,
      },
    };
    res.json(newObj);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post("/user/login", async (req, res) => {
  try {
    const userToFind = await User.findOne({ email: req.body.email });
    //   console.log(userToFind);

    if (!userToFind) {
      return res.status(401).json("Email ou password incorrect");
    }

    const newHash = SHA256(req.body.password + userToFind.salt).toString(
      encBase64
    );

    if (newHash === userToFind.hash) {
      const newObj = {
        _id: userToFind._id,
        token: userToFind.token,
        account: {
          username: userToFind.account.username,
        },
      };
      return res.json(newObj);
    } else {
      return res.status(401).json("Email ou password incorrect");
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
