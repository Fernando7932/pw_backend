import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient, Prisma } from '@prisma/client'; // <-- Importa Prisma
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { authMiddleware, AuthRequest } from './middleware/auth.middleware';

// --- NUEVAS IMPORTACIONES PARA SOCKET.IO ---
import { createServer } from 'http'; // (De Node)
import { Server } from 'socket.io'; // (De 'socket.io')

// Inicializa Prisma Client
const prisma = new PrismaClient();

const app: Application = express();
// --- CREA EL SERVIDOR HTTP ---
const httpServer = createServer(app);

// --- INICIALIZA SOCKET.IO ---
const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:5173", // Permite la conexión con tu frontend
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;

// --- CONSTANTE DE SEGURIDAD ---
const JWT_SECRET = process.env.JWT_SECRET || 'una-frase-secreta-muy-dificil-de-adivinar';
if (JWT_SECRET === 'una-frase-secreta-muy-dificil-de-adivinar') {
  console.warn('ADVERTENCIA: Estás usando el JWT_SECRET de desarrollo. ¡Cámbialo en .env!');
}

// Middlewares
app.use(cors()); // Habilita CORS
app.use(express.json()); // Permite parsear JSON del body

// --- ================================== ---
// ---      LÓGICA DE SUBIR DE NIVEL      ---
// --- ================================== ---

// --- ¡NUEVA FUNCIÓN! ---
// (RF-11, RF-13)
// Revisa si el usuario debe subir de nivel
const checkAndApplyLevelUp = async (
  // (Cambiamos 'tx' para que acepte el tipo de cliente de Prisma)
  tx: Omit<PrismaClient, "$connect" | "$disconnect" | "$on" | "$transaction" | "$use" | "$extends">,
  spectatorId: string, 
  streamerId: string, 
  currentLoyaltyId: string, 
  currentPoints: number
) => {
  try {
    // 1. Obtener las reglas de nivel del streamer (ordenadas de mayor a menor)
    // (¡Usamos 'tx'!)
    const levelRules = await tx.spectatorLevelConfig.findMany({
      where: { streamerId },
      orderBy: { pointsRequired: 'desc' }
    });

    // 2. Encontrar el nivel más alto que el usuario ha alcanzado
    let newLevel = 1; // Nivel base
    for (const rule of levelRules) {
      if (currentPoints >= rule.pointsRequired) {
        newLevel = rule.level;
        break; // Salimos al encontrar el nivel más alto (por eso ordenamos 'desc')
      }
    }

    // 3. Actualizar el nivel en la base de datos
    // (¡Usamos 'tx'!)
    await tx.loyalty.update({
      where: { id: currentLoyaltyId },
      data: { level: newLevel }
    });

    // (RF-13: La notificación se emitirá desde la función que llama a esta)

    return newLevel;

  } catch (error) {
    console.error(`Error en checkAndApplyLevelUp para spectator ${spectatorId} en canal ${streamerId}:`, error);
    return 1; // Devuelve 1 en caso de error
  }
};


// --- ================================== ---
// ---      RUTAS DE API (EXPRESS)        ---
// --- ================================== ---

// Ruta de prueba
app.get('/api', (req: Request, res: Response) => {
  res.send('API de Streaming funcionando con Express, TS y Prisma!');
});

// RF-06 (Registro)
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const streamKey = `sk_${randomBytes(16).toString('hex')}`;

    const newUser = await prisma.user.create({
      data: {
        email,
        username,
        passwordHash: passwordHash,
      },
    });

    await prisma.stream.create({
        data: {
            userId: newUser.id,
            streamKey: streamKey
        }
    });

    res.status(201).json({
      id: newUser.id,
      email: newUser.email,
      username: newUser.username
    });

  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(400).json({ message: 'El email o usuario ya existe.' });
    }
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// RF-04 (Login)
app.post('/api/auth/login', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email y contraseña son requeridos.' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
             return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        const payload = {
            userId: user.id,
            username: user.username
        };

        const token = jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.status(200).json({ 
            message: "Login exitoso", 
            token: token,
            user: {
                id: user.id,
                email: user.email,
                username: user.username
            }
        });

    } catch (error: any) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Ruta Protegida (Obtener Stream Key)
app.get('/api/stream/me', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;

    if (!userId) {
      return res.status(400).json({ message: 'ID de usuario no encontrado en el token.' });
    }

    const stream = await prisma.stream.findUnique({
      where: {
        userId: userId,
      },
    });

    if (!stream) {
      return res.status(404).json({ message: 'Información de stream no encontrada para este usuario.' });
    }

    // (RF-17) Incluimos las horas de stream
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { streamHours: true }
    });

    res.status(200).json({
      title: stream.title,
      streamKey: stream.streamKey,
      isLive: stream.isLive,
      streamHours: user?.streamHours || 0 // (RF-17)
    });

  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Ruta (Obtener Streams en Vivo)
app.get('/api/streams/live', async (req: Request, res: Response) => {
  try {
    const liveStreams = await prisma.stream.findMany({
      where: { isLive: true },
      include: {
        user: { 
          select: {
            username: true
          }
        }
      }
    });
    res.status(200).json(liveStreams);
  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Endpoint Público (Para que StreamPage obtenga la clave HLS pública)
app.get('/api/stream/u/:username', async (req: Request, res: Response) => {
  try {
    const { username } = req.params;

    const stream = await prisma.stream.findFirst({
      where: {
        user: {
          username: username,
        },
        isLive: true, 
      },
      select: {
        title: true,
        streamKey: true, 
        user: {
          select: { username: true }
        }
      }
    });

    if (!stream) {
      return res.status(404).json({ message: 'Stream no encontrado o no está en vivo.' });
    }

    res.status(200).json(stream);

  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});


// --- ================================== ---
// ---     RUTAS DE WEBHOOKS (RF-20)      ---
// --- ================================== ---
// (RF-20, RF-17)

// Docker (SRS) llamará a esta ruta cuando un stream COMIENCE
app.post('/api/webhooks/on_publish', async (req: Request, res: Response) => {
  try {
    const { stream: streamKey } = req.body; 

    if (!streamKey) {
      return res.status(400).json({ message: 'No stream key provided (stream)' });
    }

    const stream = await prisma.stream.update({
      where: { streamKey: streamKey },
      data: {
        isLive: true,
        streamStartTime: new Date(), 
      },
    });

    console.log(`[WEBHOOK] Stream iniciado: ${stream.userId}`);

    io.emit('streams_changed');

    res.status(200).json({ error: 0, code: 0 }); 

  } catch (error: any) {
    console.error('[WEBHOOK] Error on_publish:', error.message);
    res.status(200).json({ error: 1, code: 1, message: 'Stream key no encontrada' });
  }
});

// Docker (SRS) llamará a esta ruta cuando un stream TERMINE
app.post('/api/webhooks/on_publish_done', async (req: Request, res: Response) => {
  try {
    const { stream: streamKey } = req.body; 

    if (!streamKey) {
      return res.status(400).json({ message: 'No stream key provided (stream)' });
    }

    const stream = await prisma.stream.findUnique({
      where: { streamKey: streamKey },
    });

    if (!stream || !stream.streamStartTime) {
      return res.status(404).json({ message: 'Stream no encontrado o ya estaba apagado' });
    }

    await prisma.stream.update({
      where: { streamKey: streamKey },
      data: {
        isLive: false,
        streamStartTime: null, 
      },
    });

    const durationInMs = new Date().getTime() - stream.streamStartTime.getTime();
    const durationInHours = durationInMs / (1000 * 60 * 60);

    const updatedUser = await prisma.user.update({
      where: { id: stream.userId },
      data: {
        streamHours: {
          increment: durationInHours,
        },
      },
    });

    console.log(`[WEBHOOK] Stream terminado: ${updatedUser.username}. Duración: ${durationInHours.toFixed(2)} horas.`);

    io.emit('streams_changed');

    res.status(200).json({ error: 0, code: 0 }); 

  } catch (error: any) {
    console.error('[WEBHOOK] Error on_publish_done:', error.message);
    res.status(500).json({ error: 1, code: 1, message: 'Error interno del servidor' });
  }
});


// --- ================================== ---
// ---  MÓDULO 3: ECONOMÍA (REGALOS)      ---
// --- ================================== ---

// (RF-07) Obtener las monedas globales del usuario
app.get('/api/user/coins', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user?.userId },
      select: {
        coins: true
      }
    });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.status(200).json(user);
  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Iniciar el servidor
// ¡IMPORTANTE! Usamos httpServer.listen() en lugar de app.listen()
httpServer.listen(PORT, () => {
  console.log(`🚀 Servidor API y Chat corriendo en http://localhost:${PORT}`);