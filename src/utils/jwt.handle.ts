import pkg from "jsonwebtoken";
import jwt from "jsonwebtoken";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (id:string) => {
    const jwt = sign({id}, JWT_SECRET, {expiresIn: '20s'});
    return jwt;
};

const generateRefreshToken = (id: string) => {
    const refreshSecret = process.env.JWT_REFRESH_SECRET || "refresh_secret_key";
    const rjwt = sign({id}, refreshSecret, {expiresIn: '300s'});
    return rjwt
  };

const verifyToken = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET);
    return isOk;

};

const verifyRefreshToken = (token: string) => {
    try {
        const refreshSecret = process.env.JWT_REFRESH_SECRET || "refresh_secret_key";
        const decoded = jwt.verify(token, refreshSecret); // 使用 refresh token 的密钥 
        return decoded; // 返回解码后的数据
    } catch (error) {
        console.error("Invalid refresh token:", (error as Error).message);
        return null; // 如果验证失败，返回 null
    }
};

export { generateToken, verifyToken, generateRefreshToken, verifyRefreshToken };