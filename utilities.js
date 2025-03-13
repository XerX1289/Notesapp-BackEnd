const jwt = require('jsonwebtoken')

function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // console.log('Token:', token); // Log the token

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.error('Token verification error:', err); // Log the error
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    })
}
module.exports={
    authenticateToken,
}