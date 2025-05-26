require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize'); // Op está aqui
const { body, validationResult } = require('express-validator');

const app = express();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? {
      require: true,
      rejectUnauthorized: true,
    } : false,
  }
});

// Modelos (sem alterações aqui)
const User = sequelize.define('User', { /* ... */ }, { tableName: 'user', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });
const Veiculo = sequelize.define('Veiculo', { /* ... */ }, { tableName: 'veiculo', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });
User.hasMany(Veiculo, { foreignKey: 'user_id', allowNull: false });
Veiculo.belongsTo(User, { foreignKey: 'user_id', allowNull: false });
const Vaga = sequelize.define('Vaga', { /* ... */ }, { tableName: 'vaga', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });


// Middlewares
app.use(express.json());

const allowedOrigins = ['http://localhost:8081', 'http://localhost:3000'];
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    console.log("[CORS] Checando origem:", origin); // Log para depurar CORS
    if (!origin || allowedOrigins.includes(origin)) { // Usar includes para mais robustez
      console.log("[CORS] Origem permitida:", origin);
      callback(null, true);
    } else {
      console.error("[CORS] Origem BLOQUEADA:", origin);
      callback(new Error(`A origem ${origin} não é permitida por CORS.`)); // Mensagem de erro mais clara
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Middleware JWT (sem alterações aqui)
const authenticateJWT = (req, res, next) => { /* ... */ };


// --- ROTAS ---

// Rotas de /register, /login, /add-vehicle, /api/my-vehicles, /api/vagas (GET)
// (Mantidas como na sua última versão, sem alterações aqui para focar na rota de reserva)
// ...
// Registro de usuário
app.post('/register', [
  body('nome').not().isEmpty().trim().withMessage('Nome é obrigatório.'),
  body('email').isEmail().normalizeEmail().withMessage('Email inválido.'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { nome, email, senha } = req.body;
    const userExists = await User.findOne({ where: { email } });
    if (userExists) return res.status(409).json({ message: 'Este e-mail já está cadastrado.' });

    const hashedPassword = await bcrypt.hash(senha, 10);
    const newUser = await User.create({ nome, email, senha: hashedPassword });
    res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser.id });
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).json({ message: "Erro interno ao registrar usuário." });
  }
});

// Login
app.post('/login', [
  body('email').isEmail().normalizeEmail().withMessage('Email inválido.'),
  body('senha').not().isEmpty().withMessage('Senha é obrigatória.'),
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

// Adicionar veículo
app.post('/add-vehicle', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa deve ter 7 caracteres.'),
  body('modelo').not().isEmpty().trim().withMessage('Modelo é obrigatório.'),
  body('marca').not().isEmpty().trim().withMessage('Marca é obrigatória.'),
  body('cor').not().isEmpty().trim().withMessage('Cor é obrigatória.'),
  body('tipo').optional().trim(),
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
        return res.status(409).json({ message: `Veículo com placa ${req.body.placa} já existe no sistema.` });
    }
    res.status(500).json({ message: "Erro interno ao adicionar veículo." });
  }
});

// Listar veículos do usuário logado
app.get('/api/my-vehicles', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId;
    const veiculos = await Veiculo.findAll({ where: { user_id: userId } });
    res.status(200).json(veiculos); // Retorna array vazio se não tiver veículos, o que é ok
  } catch (error) {
    console.error("Erro ao listar veículos do usuário:", error);
    res.status(500).json({ message: "Erro interno ao buscar seus veículos." });
  }
});


// Listar vagas
app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    const vagas = await Vaga.findAll({ order: [['nome', 'ASC']] });
    res.status(200).json(vagas);
  } catch (error) {
    console.error("Erro ao listar vagas:", error);
    res.status(500).json({ message: "Erro interno ao listar vagas." });
  }
});


// -------- ROTA DE RESERVA MODIFICADA --------
app.post('/api/vagas/:id/reservar', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa inválida (deve ter 7 caracteres).'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const vagaId = req.params.id; // ID da vaga que se quer reservar
    const { placa } = req.body;   // Placa do veículo para a reserva
    const userIdFromToken = req.user.userId; // ID do usuário fazendo a requisição

    // Log inicial crucial
    console.log(`[API /reservar] Tentativa: UserID ${userIdFromToken} | Placa ${placa} | VagaID ${vagaId}`);
    if (!userIdFromToken) {
        console.error("[API /reservar] ERRO CRÍTICO: userIdFromToken é nulo ou indefinido. Verifique o middleware JWT e a geração do token.");
        return res.status(500).json({ message: "Erro interno: Falha na identificação do usuário." });
    }

    // VALIDAÇÃO 1: A placa pertence ao usuário logado?
    const veiculoDoUsuario = await Veiculo.findOne({
      where: {
        placa: placa,
        user_id: userIdFromToken
      },
    });

    if (!veiculoDoUsuario) {
      console.log(`[API /reservar] FALHA Val1: Placa ${placa} não pertence ao UserID ${userIdFromToken} ou não está cadastrada para ele.`);
      // Para dar uma mensagem mais específica, verificamos se a placa existe para outro usuário
      const veiculoExiste = await Veiculo.findOne({ where: { placa: placa } });
      if (veiculoExiste) {
        console.log(`[API /reservar] Info Val1: Placa ${placa} existe, mas para user_id ${veiculoExiste.user_id}.`);
        return res.status(403).json({ message: `A placa ${placa} está associada a outro usuário.` });
      }
      return res.status(404).json({ message: `Veículo com placa ${placa} não encontrado em seus registros. Por favor, cadastre o veículo.` });
    }
    console.log(`[API /reservar] SUCESSO Val1: Placa ${placa} pertence ao UserID ${userIdFromToken}.`);

    // VALIDAÇÃO 2: A placa já está em uso em OUTRA vaga ocupada?
    const outraVagaComMesmaPlaca = await Vaga.findOne({
      where: {
        placa: placa,
        ocupada: true,
        id: { [Op.ne]: vagaId } // [Op.ne] significa "não é igual a" (not equal)
      }
    });

    if (outraVagaComMesmaPlaca) {
      console.log(`[API /reservar] FALHA Val2: Placa ${placa} já está ocupando a Vaga ${outraVagaComMesmaPlaca.nome} (ID: ${outraVagaComMesmaPlaca.id}).`);
      return res.status(409).json({ message: `O veículo com placa ${placa} já está utilizando a vaga ${outraVagaComMesmaPlaca.nome}. Não é possível reservar duas vagas com o mesmo veículo.` });
    }
    console.log(`[API /reservar] SUCESSO Val2: Placa ${placa} não está em uso em outra vaga.`);

    // VALIDAÇÃO 3: A vaga alvo (vagaId) existe?
    const vagaAlvo = await Vaga.findByPk(vagaId);
    if (!vagaAlvo) {
      console.log(`[API /reservar] FALHA Val3: Vaga alvo com ID ${vagaId} não encontrada.`);
      return res.status(404).json({ message: 'A vaga que você tentou reservar não existe.' });
    }
    console.log(`[API /reservar] SUCESSO Val3: Vaga alvo ${vagaAlvo.nome} (ID: ${vagaId}) encontrada.`);

    // VALIDAÇÃO 4: A vaga alvo já está ocupada?
    if (vagaAlvo.ocupada) {
      // Se já estiver ocupada pela MESMA placa, é uma tentativa de re-reserva (geralmente um erro do cliente ou UI)
      if (vagaAlvo.placa === placa) {
        console.log(`[API /reservar] INFO Val4: Vaga ${vagaAlvo.nome} já está reservada para esta placa ${placa}.`);
        return res.status(409).json({ message: `A vaga ${vagaAlvo.nome} já está reservada para o veículo ${placa}.` });
      }
      // Se estiver ocupada por OUTRA placa
      console.log(`[API /reservar] FALHA Val4: Vaga ${vagaAlvo.nome} já está ocupada pela placa ${vagaAlvo.placa}.`);
      return res.status(400).json({ message: `A vaga ${vagaAlvo.nome} já está ocupada por outro veículo.` });
    }
    console.log(`[API /reservar] SUCESSO Val4: Vaga ${vagaAlvo.nome} está disponível.`);

    // Se todas as validações passaram, pode reservar.
    vagaAlvo.ocupada = true;
    vagaAlvo.placa = placa;
    await vagaAlvo.save();

    console.log(`[API /reservar] SUCESSO FINAL: Vaga ${vagaAlvo.nome} reservada para placa ${placa} pelo UserID ${userIdFromToken}.`);
    res.status(200).json({
      message: `Vaga ${vagaAlvo.nome} reservada com sucesso para o veículo ${placa}!`,
      vaga: { // Retorna os detalhes da vaga atualizada para o frontend
        id: vagaAlvo.id,
        nome: vagaAlvo.nome,
        ocupada: vagaAlvo.ocupada,
        placa: vagaAlvo.placa,
      },
    });

  } catch (error) {
    console.error("[API /reservar] ERRO GERAL NA ROTA:", error);
    res.status(500).json({ message: 'Erro interno ao tentar processar sua reserva.' });
  }
});
// -------- FIM DA ROTA DE RESERVA MODIFICADA --------


// Rota /api/vagas/:id/liberar (Mantida como na sua última versão)
app.post('/api/vagas/:id/liberar', authenticateJWT, async (req, res) => { /* ... */ });


// Middleware de tratamento de erros global (Mantido como na sua última versão)
app.use((err, req, res, next) => { /* ... */ });


// Start server e createInitialVagas (Mantido como na sua última versão)
const port = process.env.PORT || 3000;
async function createInitialVagas() { /* ... */ }
async function startServer() { /* ... */ }
startServer();