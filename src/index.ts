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

// (RF-08, RF-11) Obtener los puntos/nivel de un usuario PARA UN CANAL
app.get('/api/user/loyalty/:streamerUsername', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { streamerUsername } = req.params;
  const spectatorId = req.user?.userId;

  try {
    const streamer = await prisma.user.findUnique({ where: { username: streamerUsername }});
    if (!streamer) return res.status(404).json({ message: "Streamer no encontrado" });

    // 1. Obtener la lealtad actual (puntos y nivel)
    const loyalty = await prisma.loyalty.findUnique({
      where: {
        spectatorId_streamerId: {
          spectatorId: spectatorId!,
          streamerId: streamer.id
        }
      },
      select: { points: true, level: true }
    });
    
    const currentPoints = loyalty?.points || 0;
    const currentLevel = loyalty?.level || 1;

    // 2. Obtener los puntos para el *siguiente* nivel
    const nextLevelConfig = await prisma.spectatorLevelConfig.findFirst({
      where: {
        streamerId: streamer.id,
        level: currentLevel + 1 // Buscamos el siguiente nivel
      },
      orderBy: { pointsRequired: 'asc' } 
    });

    // 3. Devolver el estado completo (RF-11)
    res.status(200).json({
      points: currentPoints,
      level: currentLevel,
      pointsForNextLevel: nextLevelConfig?.pointsRequired || null // null si es el nivel máximo
    });
    
  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});


// (RF-09) Obtener la lista de regalos DE UN STREAMER ESPECÍFICO
app.get('/api/gifts/:streamerUsername', async (req: Request, res: Response) => {
  try {
    const { streamerUsername } = req.params;
    
    const userWithGifts = await prisma.user.findUnique({
      where: { username: streamerUsername },
      include: { 
        gifts: true // Incluye la lista de regalos
      }
    });

    if (!userWithGifts) {
      return res.status(404).json({ message: "Streamer no encontrado." });
    }
    
    res.status(200).json(userWithGifts.gifts);
    
  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// (RF-15) "Enviar" un regalo (La transacción)
app.post('/api/gifts/send', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { giftId, toStreamerUsername } = req.body;
  const spectatorId = req.user?.userId;
  const spectatorUsername = req.user?.username; // (Necesitamos el username para el RF-13)

  if (!giftId || !toStreamerUsername || !spectatorId || !spectatorUsername) {
    return res.status(400).json({ message: 'Datos incompletos.' });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      
      const gift = await tx.gift.findUnique({ 
        where: { id: giftId },
        include: { streamer: true } 
      });
      
      if (!gift) throw new Error('Regalo no encontrado.');

      if (gift.streamer.username !== toStreamerUsername) {
        throw new Error('Regalo no pertenece a este streamer.');
      }
      
      const spectator = await tx.user.findUnique({ where: { id: spectatorId } });
      if (!spectator) throw new Error('Espectador no encontrado.');

      if (spectator.coins < gift.cost) {
        throw new Error('No tienes suficientes monedas.');
      }

      // 3. Restar monedas al espectador
      const updatedSpectator = await tx.user.update({
        where: { id: spectatorId },
        data: {
          coins: { decrement: gift.cost },
        },
        select: { coins: true, username: true } // Devolvemos las monedas actualizadas
      });

      // 4. Buscar o crear la entrada de Lealtad
      const loyalty = await tx.loyalty.upsert({
        where: { 
          spectatorId_streamerId: {
            spectatorId: spectatorId,
            streamerId: gift.streamerId
          }
        },
        create: {
          spectatorId: spectatorId,
          streamerId: gift.streamerId,
          points: gift.points // Puntos iniciales
        },
        update: {
          points: { increment: gift.points } // Sumar puntos
        },
        select: { id: true, points: true, level: true, streamerId: true }
      });
      
      // --- ¡LÓGICA ACTUALIZADA (RF-13)! ---
      const oldLevel = loyalty.level; // (Guardamos el nivel ANTES de chequear)
      
      // 5. Llamar a la función de subir de nivel
      const finalLevel = await checkAndApplyLevelUp(
          tx, 
          spectatorId,
          loyalty.streamerId,
          loyalty.id,
          loyalty.points
      );

      // --- ¡NUEVA LÓGICA (RF-13)! ---
      // (Si el nivel cambió, notificar al chat)
      if (finalLevel > oldLevel) {
        io.to(toStreamerUsername).emit('levelUp', {
          username: spectatorUsername,
          newLevel: finalLevel,
          timestamp: new Date().toISOString()
        });
      }

      // (RF-21: Emitir evento para el overlay animado)
      const giftPayload = {
        spectatorUsername: updatedSpectator.username,
        giftName: gift.name,
        timestamp: new Date().toISOString()
      };
      io.to(toStreamerUsername).emit('newGift', giftPayload);

      return { 
        newCoins: updatedSpectator.coins, 
        newLoyalty: { ...loyalty, level: finalLevel, points: loyalty.points } 
      };
    }, 
    {
      timeout: 10000 // 10 segundos (en lugar de 5000ms)
    });

    // Devolvemos las nuevas estadísticas del espectador
    res.status(200).json(result);

  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// (RF-14) Comprar packs de monedas (UI de prueba)
app.post('/api/user/buy-coins-test', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { amount } = req.body;
  const userId = req.user?.userId;

  if (!amount || !userId) {
    return res.status(400).json({ message: 'Datos incompletos.' });
  }

  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        coins: { increment: amount }
      },
      select: {
        coins: true
      }
    });

    // Devolvemos solo las monedas actualizadas
    res.status(200).json(updatedUser);

  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// (RF-22) Crear un nuevo regalo
app.post('/api/stream/gifts', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { name, cost, points } = req.body;
  const streamerId = req.user?.userId;

  if (!name || cost === undefined || points === undefined || !streamerId) {
    return res.status(400).json({ message: 'Datos incompletos.' });
  }

  try {
    const newGift = await prisma.gift.create({
      data: {
        name,
        cost: Number(cost),
        points: Number(points),
        streamer: { // Conectamos con el streamer logueado
          connect: { id: streamerId }
        }
      }
    });
    res.status(201).json(newGift);
  } catch (error: any) {
    res.status(500).json({ message: 'Error al crear el regalo', error: error.message });
  }
});

// (RF-22) Borrar un regalo
app.delete('/api/stream/gifts/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const streamerId = req.user?.userId;

  if (!streamerId) {
    return res.status(401).json({ message: 'No autenticado.' });
  }

  try {
    const gift = await prisma.gift.findFirst({
      where: {
        id: id,
        streamer: { 
          id: streamerId 
        }
      }
    });

    if (!gift) {
      return res.status(404).json({ message: 'Regalo no encontrado o no tienes permiso para borrarlo.' });
    }

    await prisma.gift.delete({
      where: { id: id }
    });

    res.status(204).send(); 

  } catch (error: any) {
    res.status(500).json({ message: 'Error al borrar el regalo', error: error.message });
  }
});

// (RF-23) Obtener las reglas de nivel del streamer
app.get('/api/stream/levels', authMiddleware, async (req: AuthRequest, res: Response) => {
    const streamerId = req.user?.userId;

    if (!streamerId) {
        return res.status(401).json({ message: 'No se pudo identificar al streamer desde el token.' });
    }

    try {
        const levels = await prisma.spectatorLevelConfig.findMany({
            where: { streamerId: streamerId }, 
            orderBy: { level: 'asc' }
        });
        res.status(200).json(levels);
    } catch (error: any) {
        console.error(`[ERROR] /api/stream/levels (User: ${streamerId}):`, error);
        res.status(500).json({ message: 'Error al obtener niveles', error: error.message });
    }
});

// (RF-23) Crear una nueva regla de nivel
app.post('/api/stream/levels', authMiddleware, async (req: AuthRequest, res: Response) => {
    const streamerId = req.user?.userId;
    const { level, pointsRequired } = req.body;

    if (!streamerId || level === undefined || pointsRequired === undefined) {
        return res.status(400).json({ message: 'Datos incompletos.' });
    }
    try {
        const newLevel = await prisma.spectatorLevelConfig.create({
            data: {
                level: Number(level),
                pointsRequired: Number(pointsRequired),
                streamer: { connect: { id: streamerId } }
            }
        });
        res.status(201).json(newLevel);
    } catch (error: any) {
         if (error.code === 'P2002') { // Unique constraint
            return res.status(400).json({ message: 'Ya existe una regla para ese nivel.' });
         }
        res.status(500).json({ message: 'Error al crear nivel', error: error.message });
    }
});

// (RF-23) Borrar una regla de nivel
app.delete('/api/stream/levels/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
    const streamerId = req.user?.userId;
    const { id: levelId } = req.params;

    if (!streamerId) {
      return res.status(401).json({ message: 'No autenticado.' });
    }

    try {
        // Verificación de propiedad
        const levelConfig = await prisma.spectatorLevelConfig.findFirst({
            where: { id: levelId, streamerId: streamerId }
        });

        if (!levelConfig) {
            return res.status(404).json({ message: 'Regla de nivel no encontrada o no te pertenece.' });
        }

        await prisma.spectatorLevelConfig.delete({ where: { id: levelId } });
        res.status(204).send();
    } catch (error: any) {
        res.status(500).json({ message: 'Error al borrar nivel', error: error.message });
    }
});


// --- ================================== ---
// ---      LÓGICA DEL CHAT (SOCKET.IO)   ---
// --- ================================== ---

io.on('connection', (socket) => {
  console.log('Un cliente se ha conectado:', socket.id);

  // Módulo 1 - Tarea 3: Unirse a sala
  socket.on('joinRoom', (roomName: string) => {
    socket.join(roomName);
    console.log(`Socket ${socket.id} se unió a la sala: ${roomName}`);
  });

  // Módulo 1 - Tarea 4: Enviar mensaje
  // (RF-10, RF-12)
  socket.on('sendMessage', async (data) => {
    const { roomName, message, token } = data;

    try {
      // 1. Autenticar el usuario del socket
      const payload = jwt.verify(token, JWT_SECRET) as { userId: string, username: string };
      
      const streamer = await prisma.user.findUnique({ where: { username: roomName }});
      if (!streamer) { throw new Error("Streamer no encontrado"); }

      // 2. Buscar o crear la entrada de Lealtad
      const loyalty = await prisma.loyalty.upsert({
        where: { 
          spectatorId_streamerId: {
            spectatorId: payload.userId,
            streamerId: streamer.id
          }
        },
        create: {
          spectatorId: payload.userId,
          streamerId: streamer.id,
          points: 1 // 1 punto por el primer mensaje
        },
        update: {
          points: { increment: 1 } // Sumar 1 punto por mensaje (RF-10)
        },
        select: { id: true, points: true, level: true, streamerId: true }
      });
      
      // --- ¡LÓGICA ACTUALIZADA (RF-13)! ---
      const oldLevel = loyalty.level; // (Guardamos el nivel ANTES de chequear)

      // 3. Llamar a la función de subir de nivel
      const finalLevel = await checkAndApplyLevelUp(
          prisma, 
          payload.userId,
          loyalty.streamerId,
          loyalty.id,
          loyalty.points
      );
      
      // --- ¡NUEVA LÓGICA (RF-13)! ---
      // (Si el nivel cambió, notificar al chat)
      if (finalLevel > oldLevel) {
        io.to(roomName).emit('levelUp', {
          username: payload.username,
          newLevel: finalLevel,
          timestamp: new Date().toISOString()
        });
      }

      // 4. Crear el objeto del mensaje
      const messagePayload = {
        username: payload.username,
        level: finalLevel, // (RF-12) ¡Usamos el nivel actualizado!
        text: message,
        timestamp: new Date().toISOString()
      };

      // 5. Retransmitir a la sala
      io.to(roomName).emit('newMessage', messagePayload);

    } catch (error) {
      // Si el token es inválido, no hacemos nada o emitimos un error
      console.error('Error al enviar mensaje (token inválido?):', error);
      socket.emit('authError', { message: 'Token inválido. No se pudo enviar el mensaje.' });
    }
  });

  socket.on('disconnect', () => {
    console.log('Un cliente se ha desconectado:', socket.id);
  });
});


// Iniciar el servidor
// ¡IMPORTANTE! Usamos httpServer.listen() en lugar de app.listen()
httpServer.listen(PORT, () => {
  console.log(`🚀 Servidor API y Chat corriendo en http://localhost:${PORT}`);
});
