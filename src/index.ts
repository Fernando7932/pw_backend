import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient, Prisma } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { authMiddleware, AuthRequest } from './middleware/auth.middleware';

// ==========================================
// 1. CONFIGURACIÓN DE SERVIDOR Y LIBRERÍAS
// ==========================================

import { createServer } from 'http'; 
import { Server } from 'socket.io'; 

// Inicialización del cliente de Base de Datos
const prisma = new PrismaClient();

const app: Application = express();

// Creamos un servidor HTTP nativo envolviendo a Express.
// Esto es necesario para que Socket.io y Express compartan el mismo puerto TCP.
const httpServer = createServer(app);

// Configuración de Socket.io con política CORS abierta
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;

// Configuración de seguridad para Tokens
const JWT_SECRET = process.env.JWT_SECRET || '#967C7C@82A8A5*';
if (JWT_SECRET === '#967C7C@82A8A5*') {
  console.warn('JWT_SECRET de desarrollo');
}

// Middlewares globales
app.use(cors()); 
app.use(express.json()); 

// ==========================================
// 2. LÓGICA AUXILIAR (SISTEMA DE NIVELES)
// ==========================================

/**
 * Función: checkAndApplyLevelUp
 * ------------------------------------------------------------------
 * Calcula si un usuario debe subir de nivel basándose en sus puntos.
 * Se ejecuta dentro de una transacción para garantizar integridad.
 * * @param tx - Contexto de transacción de Prisma (para operaciones atómicas)
 * @param spectatorId - ID del espectador
 * @param streamerId - ID del canal
 * @param currentLoyaltyId - ID del registro de lealtad
 * @param currentPoints - Puntos totales acumulados
 */
const checkAndApplyLevelUp = async (
  tx: Omit<PrismaClient, "$connect" | "$disconnect" | "$on" | "$transaction" | "$use" | "$extends">,
  spectatorId: string, 
  streamerId: string, 
  currentLoyaltyId: string, 
  currentPoints: number
) => {
  try {
    // A. Obtener configuración de niveles del streamer (Orden descendente por puntos requeridos)
    const levelRules = await tx.spectatorLevelConfig.findMany({
      where: { streamerId },
      orderBy: { pointsRequired: 'desc' }
    });

    // B. Determinar el nivel máximo alcanzado
    let newLevel = 1; // Nivel base por defecto
    for (const rule of levelRules) {
      if (currentPoints >= rule.pointsRequired) {
        newLevel = rule.level;
        break; // Al estar ordenado descendente, el primero que coincida es el más alto
      }
    }

    // C. Actualizar el nivel en la base de datos
    await tx.loyalty.update({
      where: { id: currentLoyaltyId },
      data: { level: newLevel }
    });
    
    // Retorna el nuevo nivel para notificaciones posteriores
    return newLevel;

  } catch (error) {
    console.error(`Error en checkAndApplyLevelUp para spectator ${spectatorId} en canal ${streamerId}:`, error);
    return 1; // Retorno seguro en caso de fallo
  }
};


// ==========================================
// 3. API REST: AUTENTICACIÓN Y USUARIOS
// ==========================================

// Health Check
app.get('/api', (req: Request, res: Response) => {
  res.send('API de Streaming funcionando con Express, TS y Prisma!');
});

// Registro de usuarios
// Crea el usuario, hashea la contraseña y genera la Stream Key única
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    // Generación de clave hexadecimal aleatoria para OBS/SRS
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

// Inicio de Sesión
// Valida credenciales y emite un JWT
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

// ==========================================
// 4. API REST: GESTIÓN DE STREAMS
// ==========================================

// Obtener Stream Key (Privado - Solo para el dueño)
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
    
    // Incluye estadísticas de horas transmitidas
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { streamHours: true }
    });

    res.status(200).json({
      title: stream.title,
      streamKey: stream.streamKey,
      isLive: stream.isLive,
      streamHours: user?.streamHours || 0 
    });

  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Listar canales en vivo (Público)
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

// Obtener datos públicos de un stream (Para reproductor HLS)
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


// ==========================================
// 5. WEBHOOKS (CONEXIÓN CON SERVIDOR SRS)
// ==========================================

// Webhook: Inicio de transmisión (on_publish)
// Se llama cuando el software de streaming conecta con el servidor RTMP
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
    
    // Notifica a todos los clientes para actualizar la lista de streams
    io.emit('streams_changed');
    
    // Código 0 indica éxito al servidor SRS
    res.status(200).json({ error: 0, code: 0 }); 

  } catch (error: any) {
    console.error('[WEBHOOK] Error on_publish:', error.message);
    res.status(200).json({ error: 1, code: 1, message: 'Stream key no encontrada' });
  }
});

// Webhook: Fin de transmisión (on_publish_done)
// Se llama cuando se corta la conexión RTMP
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

    // Calculamos duración de la sesión
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


// ==========================================
// 6. ECONOMÍA: MONEDAS, REGALOS Y LEALTAD
// ==========================================

// Consultar saldo de monedas del usuario logueado
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

// Consultar progreso de nivel en un canal específico
// Devuelve puntos actuales, nivel actual y meta para el siguiente
app.get('/api/user/loyalty/:streamerUsername', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { streamerUsername } = req.params;
  const spectatorId = req.user?.userId;

  try {
    const streamer = await prisma.user.findUnique({ where: { username: streamerUsername }});
    if (!streamer) return res.status(404).json({ message: "Streamer no encontrado" });

    // A. Obtener lealtad actual
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

    // B. Calcular siguiente meta
    const nextLevelConfig = await prisma.spectatorLevelConfig.findFirst({
      where: {
        streamerId: streamer.id,
        level: currentLevel + 1 // Buscamos el siguiente nivel
      },
      orderBy: { pointsRequired: 'asc' } 
    });

    res.status(200).json({
      points: currentPoints,
      level: currentLevel,
      pointsForNextLevel: nextLevelConfig?.pointsRequired || null // null indica nivel máximo
    });
    
  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});


// Obtener catálogo de regalos disponibles de un streamer
app.get('/api/gifts/:streamerUsername', async (req: Request, res: Response) => {
  try {
    const { streamerUsername } = req.params;
    
    const userWithGifts = await prisma.user.findUnique({
      where: { username: streamerUsername },
      include: { 
        gifts: true 
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

// Envío de Regalos (Transacción Completa)
// Maneja cobro, entrega de puntos, cálculo de nivel y notificaciones Socket
app.post('/api/gifts/send', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { giftId, toStreamerUsername } = req.body;
  const spectatorId = req.user?.userId;
  const spectatorUsername = req.user?.username; 

  if (!giftId || !toStreamerUsername || !spectatorId || !spectatorUsername) {
    return res.status(400).json({ message: 'Datos incompletos.' });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      
      // 1. Validar existencia del regalo
      const gift = await tx.gift.findUnique({ 
        where: { id: giftId },
        include: { streamer: true } 
      });
      
      if (!gift) throw new Error('Regalo no encontrado.');

      if (gift.streamer.username !== toStreamerUsername) {
        throw new Error('Regalo no pertenece a este streamer.');
      }
      
      // 2. Validar fondos del usuario
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
        select: { coins: true, username: true } 
      });

      // 4. Buscar o crear la entrada de Lealtad (Upsert)
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
      
      // 5. Verificar Subida de Nivel
      const oldLevel = loyalty.level; // (Guardamos el nivel ANTES de chequear)
      
      const finalLevel = await checkAndApplyLevelUp(
          tx, 
          spectatorId,
          loyalty.streamerId,
          loyalty.id,
          loyalty.points
      );

      // 6. Notificación de Level Up vía Socket (si aplica)
      if (finalLevel > oldLevel) {
        io.to(toStreamerUsername).emit('levelUp', {
          username: spectatorUsername,
          newLevel: finalLevel,
          timestamp: new Date().toISOString()
        });
      }

      // 7. Notificación del Regalo (Animación en Overlay)
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
      timeout: 10000 // Timeout extendido a 10s por seguridad
    });

    res.status(200).json(result);

  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

// Comprar packs de monedas (Simulado para pruebas)
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

    res.status(200).json(updatedUser);

  } catch (error: any) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Crear un nuevo regalo (Dashboard Streamer)
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

// Borrar un regalo
app.delete('/api/stream/gifts/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const streamerId = req.user?.userId;

  if (!streamerId) {
    return res.status(401).json({ message: 'No autenticado.' });
  }

  try {
    // Verificar propiedad del regalo antes de borrar
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

// Obtener las reglas de nivel del streamer
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

// Crear una nueva regla de nivel
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
         if (error.code === 'P2002') { // Restricción única de Prisma
            return res.status(400).json({ message: 'Ya existe una regla para ese nivel.' });
         }
        res.status(500).json({ message: 'Error al crear nivel', error: error.message });
    }
});

// Borrar una regla de nivel
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


// ==========================================
// 7. CHAT EN TIEMPO REAL (SOCKET.IO)
// ==========================================

io.on('connection', (socket) => {
  console.log('Un cliente se ha conectado:', socket.id);

  // Unirse a sala de chat (nombre del streamer)
  socket.on('joinRoom', (roomName: string) => {
    socket.join(roomName);
    console.log(`Socket ${socket.id} se unió a la sala: ${roomName}`);
  });

  // Enviar mensaje y procesar gamificación
  socket.on('sendMessage', async (data) => {
    const { roomName, message, token } = data;

    try {
      // A. Autenticar el usuario del socket mediante JWT
      const payload = jwt.verify(token, JWT_SECRET) as { userId: string, username: string };
      
      const streamer = await prisma.user.findUnique({ where: { username: roomName }});
      if (!streamer) { throw new Error("Streamer no encontrado"); }

      // B. Asignar puntos por interacción (chat)
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
          points: { increment: 1 } // Sumar 1 punto por mensaje
        },
        select: { id: true, points: true, level: true, streamerId: true }
      });
      
      // C. Verificar y aplicar nivel
      const oldLevel = loyalty.level; 

      const finalLevel = await checkAndApplyLevelUp(
          prisma, 
          payload.userId,
          loyalty.streamerId,
          loyalty.id,
          loyalty.points
      );
      
      // D. Notificar Level Up
      if (finalLevel > oldLevel) {
        io.to(roomName).emit('levelUp', {
          username: payload.username,
          newLevel: finalLevel,
          timestamp: new Date().toISOString()
        });
      }

      // E. Retransmitir mensaje al resto de la sala
      const messagePayload = {
        username: payload.username,
        level: finalLevel, // Enviamos el nivel actualizado
        text: message,
        timestamp: new Date().toISOString()
      };

      io.to(roomName).emit('newMessage', messagePayload);

    } catch (error) {
      // Si el token es inválido, emitimos un error al cliente específico
      console.error('Error al enviar mensaje (token inválido?):', error);
      socket.emit('authError', { message: 'Token inválido. No se pudo enviar el mensaje.' });
    }
  });

  socket.on('disconnect', () => {
    console.log('Un cliente se ha desconectado:', socket.id);
  });
});


// INICIO DEL SERVIDOR
// Se utiliza httpServer.listen en vez de app.listen para soportar WebSockets
httpServer.listen(PORT, () => {
  console.log(`Servidor API y Chat corriendo en http://localhost:${PORT}`);
});
