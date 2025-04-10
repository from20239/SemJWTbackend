// src/routes/user_routes.ts
import express from 'express';
import {
    saveMethodHandler,
    createUserHandler,
    getAllUsersHandler,
    getUserByIdHandler,
    updateUserHandler,
    deleteUserHandler
} from '../users/user_controller.js';
import { checkJwt } from '../../middleware/session.js';
const router = express.Router();


router.get('/main', saveMethodHandler);


router.post('/users', createUserHandler);


router.get('/users', checkJwt, getAllUsersHandler);


router.get('/users/:id', getUserByIdHandler);


router.put('/users/:id', updateUserHandler);


router.delete('/users/:id', deleteUserHandler);

export default router;
