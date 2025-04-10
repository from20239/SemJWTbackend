import { encrypt, verified } from "../../utils/bcrypt.handle.js";
import { generateToken , generateRefreshToken, verifyRefreshToken} from "../../utils/jwt.handle.js";
import User, { IUser } from "../users/user_models.js";
import { Auth } from "./auth_model.js";
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { Request, Response } from "express";

const registerNewUser = async ({ email, password, name, age }: IUser) => {
    const checkIs = await User.findOne({ email });
    if(checkIs) return "ALREADY_USER";
    const passHash = await encrypt(password);
    const registerNewUser = await User.create({ 
        email, 
        password: passHash, 
        name, 
        age });
    return registerNewUser;
};

const refreshTokens = async (refreshToken: string) => {
    try {

        console.log("Starting refreshTokens function...");
        console.log("Received refreshToken:", refreshToken);

        // 验证 refresh token 的有效性
        const decoded = verifyRefreshToken(refreshToken); // 使用工具函数验证 refresh token

        console.log("Decoded refreshToken:", decoded);

        if (!decoded) {
            console.error("Invalid refresh token");
            throw new Error("Invalid refresh token");
        }

        // 从解码后的数据中获取用户的 email
        const email = (typeof decoded !== 'string' && decoded.id) ? decoded.id : null;

        console.log("Extracted email from token:", email);

        if (!email) {
            console.error("Invalid token payload: email not found");
            throw new Error("Invalid token payload");
        }

        // 检查用户是否存在
        console.log("Checking if user exists with email:", email);
        const user = await User.findOne({ email });
        console.log("User found:", user);
        if (!user) {
            console.error("User not found for email:", email);
            throw new Error("User not found");
        }

        // 生成新的 access token 和 refresh token

        console.log("Generating new tokens for user:", email);
        const newAccessToken = generateToken(email);
        const newRefreshToken = generateRefreshToken(email);

        console.log("New tokens generated:");
        console.log("Access Token:", newAccessToken);
        console.log("Refresh Token:", newRefreshToken);

        // 返回新的令牌
        console.log("=== Successfully refreshed tokens ===");
        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    } catch (error: any) {
        console.error("=== Error in refreshTokens function ===");
        console.error("Error message:", error.message);
        console.error("Error stack:", error.stack);
        throw new Error("Could not refresh tokens");
    }
};

const loginUser = async ({ email, password }: Auth) => {
    const checkIs = await User.findOne({ email });
    if(!checkIs) return "NOT_FOUND_USER";

    const passwordHash = checkIs.password; //El encriptado que ve de la bbdd
    const isCorrect = await verified(password, passwordHash);
    if(!isCorrect) return "INCORRECT_PASSWORD";

    const token = generateToken(checkIs.email);
    const refreshtoken = generateRefreshToken(checkIs.email);
    const data = {
        token,
        refreshtoken,
        user: checkIs
    }
    return data;
};

const googleAuth = async (code: string) => {

    try {
        console.log("Client ID:", process.env.GOOGLE_CLIENT_ID);
        console.log("Client Secret:", process.env.GOOGLE_CLIENT_SECRET);
        console.log("Redirect URI:", process.env.GOOGLE_OAUTH_REDIRECT_URL);
    
        if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_OAUTH_REDIRECT_URL) {
            throw new Error("Variables de entorno faltantes");
        }

        interface TokenResponse {
            access_token: string;
            expires_in: number;
            scope: string;
            token_type: string;
            id_token?: string;
        }
        //axios --> llibreria que s'utilitza per a fer peticions HTTP
        const tokenResponse = await axios.post<TokenResponse>('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
            grant_type: 'authorization_code'
        });

        const access_token = tokenResponse.data.access_token;
        console.log("Access Token:", access_token); 
        // Obté el perfil d'usuari
        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            params: { access_token},
            headers: { Accept: 'application/json',},
            
        });

        const profile = profileResponse.data as {name:string, email: string; id: string };
        console.log("Access profile:", profile); 
        // Busca o crea el perfil a la BBDD
        let user = await User.findOne({ 
            $or: [{name: profile.name},{ email: profile.email }, { googleId: profile.id }] 
        });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8);
            const passHash = await encrypt(randomPassword);
            user = await User.create({
                name: profile.name,
                email: profile.email,
                googleId: profile.id,
                password: passHash,
            });
        }

        // Genera el token JWT
        const token = generateToken(user.email);
        const RefreshToken = generateRefreshToken(user.email); // Generar el refresh token

        console.log(token);
        return { token,RefreshToken, user };

    } catch (error: any) {
        console.error('Google Auth Error:', error.response?.data || error.message); // Log detallado
        throw new Error('Error en autenticación con Google');
    }
};


export { registerNewUser, loginUser, googleAuth, refreshTokens };