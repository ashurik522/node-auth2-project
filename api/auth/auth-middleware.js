const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  if(!req.headers.authorization){
    res.status(401).json({ message: 'token required'})
    return
  } 
  jwt.verify(req.headers.authorization, JWT_SECRET, (err, decodedToken) => {
    req.jwt = decodedToken
     if(err){
      res.status(401).json({ message: 'token invalid'})
      return
    }
    next()
  })
 
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
 
}

const only = role_name => (req, res, next) => {
  if(req.jwt.role_name != role_name){
    res.status(403).json({ message: 'this is not for you'})
    return
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 next()
}


const checkUsernameExists = async (req, res, next) => {
  const result = await Users.findBy({username: req.body.username}).first()
  if(result == null){
    res.status(401).json({ message: 'invalid credentials'})
    return
  }
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
 next()
}


const validateRoleName = (req, res, next) => {

  
  if(typeof req.body.role_name != 'string' || req.body.role_name.trim() === ""){
    req.body.role_name = 'student'
  } 
  if (req.body.role_name.trim() == "admin"){
    res.status(422).json({ message: 'role name can not be admin'})
    return
  }
  if(req.body.role_name.trim().length > 32){
    res.status(422).json({ message: 'Role name can not be longer than 32 chars'})
    return
  }

  req.role_name = req.body.role_name.trim()
  

  
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
 next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
