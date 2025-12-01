import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';


// Recuperamos la clave secreta para validar la firma digital del token.
const JWT_SECRET = process.env.JWT_SECRET || '#967C7C@82A8A5*';


export interface AuthRequest extends Request {
    user?: {
        userId: string;
        username: string;
    };
}


export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    // Validamos que exista y que cumpla el estándar "Bearer <token>"
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Acceso denegado. No se proveyó un token.' });
    }

    const token = authHeader.split(' ')[1]; // Obtenemos el string del token limpio

    try {
        // Si la firma no coincide o el token expiró, jwt.verify lanzará un error automáticamente
        const payload = jwt.verify(token, JWT_SECRET) as { userId: string; username: string };

        // Guardamos los datos decodificados en 'req' para que los endpoints protegidos sepan quién es el usuario
        req.user = payload;
        
        // 'next()' indica a Express que pase el control a la siguiente función (la ruta final)
        next();

    } catch (error) {
        // Si ocurre cualquier error en la verificación, bloqueamos el acceso
        res.status(401).json({ message: 'Token inválido o expirado.' });
    }
};