import express from 'express';
import { createEntryHandler, deleteEntryHandler, getAllForumHandler, getEntryByIdHandler, updateEntryHandler } from './forum_controller.js';

const router = express.Router();

/**
 * @openapi
 * /api/forum:
 *   post:
 *     summary: Crea una nueva entrada en el foro
 *     description: Añade una nueva entrada al foro.
 *     tags:
 *       - Forum
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               comment:
 *                 type: string
 *     responses:
 *       201:
 *         description: Entrada creada exitosamente
 */
router.post('/forum', createEntryHandler);

/**
 * @openapi
 * /api/forum:
 *   get:
 *     summary: Obtiene todas las entradas del foro
 *     description: Retorna una lista de todas las entradas del foro.
 *     tags:
 *       - Forum
 *     responses:
 *       200:
 *         description: Éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                   comment:
 *                     type: string
 */
router.get('/forum', getAllForumHandler);

/**
 * @openapi
 * /api/forum/{id}:
 *   get:
 *     summary: Obtiene una entrada del foro por ID
 *     description: Retorna los detalles de una entrada específica del foro.
 *     tags:
 *       - Forum
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 name:
 *                   type: string
 *                 comment:
 *                   type: string
 *       404:
 *         description: Entrada no encontrada
 */
router.get('/forum/:id', getEntryByIdHandler);

/**
 * @openapi
 * /api/forum/{id}:
 *   put:
 *     summary: Actualiza una entrada del foro por ID
 *     description: Modifica los detalles de una entrada específica del foro.
 *     tags:
 *       - Forum
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               comment:
 *                 type: string
 *     responses:
 *       200:
 *         description: Entrada actualizada exitosamente
 *       404:
 *         description: Entrada no encontrada
 */
router.put('/forum/:id', updateEntryHandler);

/**
 * @openapi
 * /api/forum/{id}:
 *   delete:
 *     summary: Elimina una entrada del foro por ID
 *     description: Elimina una entrada específica del foro.
 *     tags:
 *       - Forum
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Entrada eliminada exitosamente
 *       404:
 *         description: Entrada no encontrada
 */
router.delete('/forum/:id', deleteEntryHandler);

export default router;
