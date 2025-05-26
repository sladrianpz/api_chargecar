require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 3000;

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: process.env.NODE_ENV === 'development' ? msg => console.log('[SEQUELIZE]', msg) : false,
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? {
      require: true,
      rejectUnauthorized: true,
    } : false,
  }
});

// --- Definições Completas dos Modelos ---
const User = sequelize.define('User', {
  nome: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  senha: { type: DataTypes.STRING, allowNull: false },
  // cpf: { type: DataTypes.STRING(11), unique: true, allowNull: true }, // Descomente se for usar
}, { tableName: 'user', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

const Veiculo = sequelize.define('Veiculo', {
  placa: { type: DataTypes.STRING(7), allowNull: false, unique: true },
  cor: { type: DataTypes.STRING(30), allowNull: false },
  modelo: { type: DataTypes.STRING(40), allowNull: false },
  marca: { type: DataTypes.STRING(40), allowNull: false },
  tipo: { type: DataTypes.STRING(50), allowNull: true },
}, { tableName: 'veiculo', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

User.hasMany(Veiculo, { foreignKey: 'user_id', allowNull: false });
Veiculo.belongsTo(User, { foreignKey: 'user_id', allowNull: false });

const Vaga = sequelize.define('Vaga', {
  nome: { type: DataTypes.STRING, allowNull: false, unique: true },
  ocupada: { type: DataTypes.BOOLEAN, defaultValue: false },
  placa: { type: DataTypes.STRING(7), allowNull: true },
}, { tableName: 'vaga', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });
// --- Fim das Definições dos Modelos ---


// Middlewares
app.use(express.json());

const allowedOrigins = ['http://localhost:8081', 'http://localhost:3000'];
if (process.env.FRONTEND_URL) allowedOrigins.push(process.env.FRONTEND_URL);
if (process.env.RENDER_PREVIEW_URL) allowedOrigins.push(process.env.RENDER_PREVIEW_URL);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`[CORS] Origem BLOQUEADA: ${origin}. Permitidas: ${allowedOrigins.join(', ')}`);
      callback(new Error(`A origem ${origin} não é permitida por CORS.`));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Acesso negado. Token não fornecido ou mal formatado.' });
  }
  const token = authHeader.replace('Bearer ', '');
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expirado.' });
      console.error("[JWT Error] Token inválido:", err.message);
      return res.status(403).json({ message: 'Token inválido.' });
    }
    req.user = decodedToken;
    next();
  });
};

// --- ROTAS ---

app.get('/', (req, res) => {
  res.status(200).send('API ChargeCar está no ar!');
});

// Preencha com a sua lógica completa para cada rota abaixo
app.post('/register', [
  body('nome').notEmpty().trim().withMessage('Nome é obrigatório.'),
  body('email').isEmail().normalizeEmail().withMessage('Email inválido.'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres.'),
  // body('cpf').optional().isLength({ min: 11, max: 11 }).isNumeric().withMessage('CPF inválido'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { nome, email, senha /*, cpf*/ } = req.body;
    let userExists = await User.findOne({ where: { email } });
    if (userExists) return res.status(409).json({ message: 'Este e-mail já está cadastrado.' });
    // if (cpf) {
    //   userExists = await User.findOne({ where: { cpf } });
    //   if (userExists) return res.status(409).json({ message: 'Este CPF já está cadastrado.' });
    // }
    const hashedPassword = await bcrypt.hash(senha, 10);
    const newUser = await User.create({ nome, email, senha: hashedPassword /*, cpf: cpf || null*/ });
    res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser.id });
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).json({ message: "Erro interno ao registrar usuário." });
  }
});

app.post('/login', [
  body('email').isEmail().normalizeEmail().withMessage('Email inválido.'),
  body('senha').notEmpty().withMessage('Senha é obrigatória.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { email, senha } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas.' });
    const validPassword = await bcrypt.compare(senha, user.senha);
    if (!validPassword) return res.status(401).json({ message: 'Credenciais inválidas.' });
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login bem-sucedido!', token, userId: user.id });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ message: "Erro interno ao fazer login." });
  }
});

app.post('/add-vehicle', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa deve ter 7 caracteres.'),
  body('modelo').notEmpty().trim().withMessage('Modelo é obrigatório.'),
  body('marca').notEmpty().trim().withMessage('Marca é obrigatória.'),
  body('cor').notEmpty().trim().withMessage('Cor é obrigatória.'),
  body('tipo').optional({ checkFalsy: true }).trim(), // checkFalsy para permitir string vazia
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { placa, modelo, marca, cor, tipo } = req.body;
    const userId = req.user.userId;
    const vehicleExistsGlobal = await Veiculo.findOne({ where: { placa } });
    if (vehicleExistsGlobal) {
      if (vehicleExistsGlobal.user_id !== userId) {
        return res.status(409).json({ message: `Veículo com placa ${placa} já cadastrado por outro usuário.` });
      }
      return res.status(409).json({ message: `Você já cadastrou o veículo com placa ${placa}.` });
    }
    const newVehicle = await Veiculo.create({ placa, modelo, marca, cor, tipo: tipo || null, user_id: userId });
    res.status(201).json({ message: 'Veículo cadastrado com sucesso!', veiculo: newVehicle });
  } catch (error) {
    console.error("Erro ao adicionar veículo:", error);
    if (error.name === 'SequelizeUniqueConstraintError') {
      return res.status(409).json({ message: `Veículo com placa ${req.body.placa} já existe (constraint).` });
    }
    res.status(500).json({ message: "Erro interno ao adicionar veículo." });
  }
});

app.get('/api/my-vehicles', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId;
    if(!userId) return res.status(403).json({message: "ID de usuário não encontrado."})
    const veiculos = await Veiculo.findAll({ where: { user_id: userId } });
    res.status(200).json(veiculos);
  } catch (error) {
    console.error("Erro ao listar veículos do usuário:", error);
    res.status(500).json({ message: "Erro ao buscar seus veículos." });
  }
});

app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    console.log(`[API /api/vagas GET] Iniciando. UserID: ${req.user?.userId}`);
    const vagas = await Vaga.findAll({ order: [['nome', 'ASC']] });
    console.log(`[API /api/vagas GET] Vagas encontradas: ${vagas?.length}`);
    res.status(200).json(vagas);
  } catch (error) {
    console.error(`[API /api/vagas GET] ERRO: ${error.message}`, error.stack);
    if (error.original) console.error(`[API /api/vagas GET] Erro Original DB:`, error.original);
    res.status(500).json({ message: "Erro grave ao buscar vagas."});
  }
});

app.post('/api/vagas/:id/reservar', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa inválida.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const vagaId = req.params.id;
    const { placa } = req.body;
    const userIdFromToken = req.user.userId;
    console.log(`[API /reservar] Tentativa: UserID ${userIdFromToken} | Placa ${placa} | VagaID ${vagaId}`);
    if (!userIdFromToken) {
        return res.status(500).json({ message: "Falha na identificação do usuário." });
    }
    const veiculoDoUsuario = await Veiculo.findOne({ where: { placa: placa, user_id: userIdFromToken } });
    if (!veiculoDoUsuario) {
      const veiculoExiste = await Veiculo.findOne({ where: { placa: placa } });
      if (veiculoExiste) return res.status(403).json({ message: `Placa ${placa} associada a outro usuário.` });
      return res.status(404).json({ message: `Veículo com placa ${placa} não encontrado nos seus registros.` });
    }
    const outraVagaComMesmaPlaca = await Vaga.findOne({ where: { placa: placa, ocupada: true, id: { [Op.ne]: vagaId } } });
    if (outraVagaComMesmaPlaca) {
      return res.status(409).json({ message: `Veículo ${placa} já utiliza a vaga ${outraVagaComMesmaPlaca.nome}.` });
    }
    const vagaAlvo = await Vaga.findByPk(vagaId);
    if (!vagaAlvo) return res.status(404).json({ message: 'Vaga alvo não existe.' });
    if (vagaAlvo.ocupada) {
      if (vagaAlvo.placa === placa) return res.status(409).json({ message: `Vaga ${vagaAlvo.nome} já reservada para ${placa}.` });
      return res.status(400).json({ message: `Vaga ${vagaAlvo.nome} já ocupada por ${vagaAlvo.placa}.` });
    }
    vagaAlvo.ocupada = true; vagaAlvo.placa = placa; await vagaAlvo.save();
    res.status(200).json({ message: `Vaga ${vagaAlvo.nome} reservada com sucesso para ${placa}!`, vaga: vagaAlvo });
  } catch (error) {
    console.error("[API /reservar] ERRO GERAL:", error);
    res.status(500).json({ message: 'Erro ao processar reserva.' });
  }
});

app.post('/api/vagas/:id/liberar', authenticateJWT, async (req, res) => {
  try {
    const vagaId = req.params.id;
    const userId = req.user.userId;
    const vaga = await Vaga.findByPk(vagaId);
    if (!vaga) return res.status(404).json({ message: "Vaga não encontrada." });
    if (!vaga.ocupada) return res.status(400).json({ message: `Vaga ${vaga.nome} já está livre.` });
    if (vaga.placa) {
        const veiculoNaVaga = await Veiculo.findOne({ where: { placa: vaga.placa, user_id: userId }});
        if (!veiculoNaVaga) {
            return res.status(403).json({ message: `Você não pode liberar esta vaga pois não foi reservada por um veículo seu.`})
        }
    }
    vaga.ocupada = false; vaga.placa = null; await vaga.save();
    res.status(200).json({ message: `Vaga ${vaga.nome} liberada com sucesso.`, vaga });
  } catch (error) {
    console.error("[API /liberar] Erro:", error);
    res.status(500).json({ message: "Erro ao liberar a vaga." });
  }
});

app.post('/api/vagas/reset-para-apresentacao-agora', async (req, res) => {
  console.warn("[API RESET APRESENTAÇÃO] ROTA ACIONADA!");
  try {
    const [affectedRows] = await Vaga.update({ ocupada: false, placa: null },{ where: {} });
    res.status(200).json({ message: `${affectedRows} vagas resetadas.` });
  } catch (error) {
    console.error("[API RESET APRESENTAÇÃO] Erro:", error);
    res.status(500).json({ message: "Erro ao resetar vagas." });
  }
});

// Middleware de tratamento de erros global
app.use((err, req, res, next) => {
  console.error("------------------------------------");
  console.error("MIDDLEWARE DE ERRO GLOBAL:", err.message);
  if (err.message.includes("não é permitida por CORS")) return res.status(403).json({ message: err.message });
  if (err.name === 'UnauthorizedError') return res.status(401).json({ message: 'Token inválido/ausente.' });
  console.error("Rota:", req.method, req.originalUrl, "Stack:", err.stack);
  res.status(500).json({ message: 'Erro inesperado no servidor.' });
});

// Funções de inicialização
async function createInitialVagas() {
  try {
    const count = await Vaga.count();
    if (count === 0) {
      const vagasParaCriar = Array.from({ length: 15 }, (_, i) => ({ nome: `Vaga ${i + 1}` }));
      await Vaga.bulkCreate(vagasParaCriar);
      console.log('[API STARTUP] 15 vagas iniciais criadas.');
    } else {
      console.log(`[API STARTUP] ${count} vagas já existem.`);
    }
  } catch (error) {
    console.error("[API STARTUP] Erro ao criar vagas iniciais:", error.message);
  }
}

async function startServer() {
  try {
    console.log('[API STARTUP] Iniciando...');
    console.log(`[API STARTUP] DATABASE_URL: ${process.env.DATABASE_URL ? 'Definida' : 'NÃO DEFINIDA!'}`);
    console.log(`[API STARTUP] DB_SSL: ${process.env.DB_SSL}`);
    console.log(`[API STARTUP] JWT_SECRET: ${process.env.JWT_SECRET ? 'Definido' : 'NÃO DEFINIDO!'}`);

    await sequelize.authenticate();
    console.log('[API STARTUP] Conectado ao DB.');

    console.log('[API STARTUP] Sincronizando modelos (alter:true)...');
    await sequelize.sync({ alter: true }); // <<--- USANDO alter:true
    console.log('[API STARTUP] Modelos sincronizados (alter:true).');

    await createInitialVagas();

    if (process.env.RESET_VAGAS_ON_STARTUP === 'true') {
        console.warn("[API STARTUP RESET] RESET_VAGAS_ON_STARTUP=true. Resetando vagas...");
        await Vaga.update({ ocupada: false, placa: null }, { where: {} });
        console.log("[API STARTUP RESET] Vagas resetadas.");
    }

    app.listen(port, () => {
      console.log(`[API STARTUP] Servidor rodando na porta ${port} (${process.env.NODE_ENV || 'development'}).`);
    });

  } catch (err) {
    console.error('[API STARTUP] ERRO CRÍTICO AO INICIAR:', err.message);
    if (err.original) console.error('Erro Original DB:', err.original);
    console.error('Stack Completo:', err.stack); // Log do stack completo
    process.exit(1);
  }
}

startServer();