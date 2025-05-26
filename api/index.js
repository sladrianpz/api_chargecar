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

// --- Definições Completas dos Modelos ---
const User = sequelize.define('User', {
  nome: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  senha: { type: DataTypes.STRING, allowNull: false },
}, { tableName: 'user', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

const Veiculo = sequelize.define('Veiculo', {
  placa: { type: DataTypes.STRING(7), allowNull: false, unique: true },
  cor: { type: DataTypes.STRING(30), allowNull: false },
  modelo: { type: DataTypes.STRING(40), allowNull: false },
  marca: { type: DataTypes.STRING(40), allowNull: false },
  tipo: { type: DataTypes.STRING(50) },
  // user_id é adicionado pela associação
}, { tableName: 'veiculo', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

// Associação User -> Veiculo
User.hasMany(Veiculo, { foreignKey: 'user_id', allowNull: false });
Veiculo.belongsTo(User, { foreignKey: 'user_id', allowNull: false });

const Vaga = sequelize.define('Vaga', {
  nome: { type: DataTypes.STRING, allowNull: false, unique: true },
  ocupada: { type: DataTypes.BOOLEAN, defaultValue: false },
  placa: { type: DataTypes.STRING(7), allowNull: true },
  // user_id_reserva: { // Se você decidir adicionar isso no futuro
  //   type: DataTypes.INTEGER,
  //   allowNull: true,
  //   references: { model: User, key: 'id' }
  // }
}, { tableName: 'vaga', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });
// --- Fim das Definições dos Modelos ---


// Middlewares
app.use(express.json());

const allowedOrigins = ['http://localhost:8081', 'http://localhost:3000'];
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    console.log("[CORS] Checando origem:", origin);
    if (!origin || allowedOrigins.includes(origin)) {
      console.log("[CORS] Origem permitida:", origin);
      callback(null, true);
    } else {
      console.error("[CORS] Origem BLOQUEADA:", origin);
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
      return res.status(403).json({ message: 'Token inválido.' });
    }
    req.user = decodedToken;
    next();
  });
};

// --- ROTAS ---
app.post('/register', [ /* ... Sua lógica de registro ... */ ], async (req, res) => { /* ... */ });
app.post('/login', [ /* ... Sua lógica de login ... */ ], async (req, res) => { /* ... */ });
app.post('/add-vehicle', authenticateJWT, [ /* ... Sua lógica de add-vehicle ... */ ], async (req, res) => { /* ... */ });
app.get('/api/my-vehicles', authenticateJWT, async (req, res) => { /* ... Sua lógica de my-vehicles ... */ });

app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    console.log(`[API /api/vagas GET] Iniciando. UserID: ${req.user?.userId}`);
    const vagas = await Vaga.findAll({ order: [['nome', 'ASC']] });
    console.log(`[API /api/vagas GET] Consulta ao banco realizada. Vagas encontradas: ${vagas?.length}`);
    res.status(200).json(vagas);
  } catch (error) {
    console.error(`[API /api/vagas GET] ERRO CAPTURADO AO LISTAR VAGAS:`, error.message);
    console.error(`[API /api/vagas GET] Stack do erro:`, error.stack);
    res.status(500).json({ message: "Ocorreu um erro ao buscar as vagas. Tente novamente mais tarde." });
  }
});

app.post('/api/vagas/:id/reservar', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa inválida (deve ter 7 caracteres).'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const vagaId = req.params.id;
    const { placa } = req.body;
    const userIdFromToken = req.user.userId;
    console.log(`[API /reservar] Tentativa: UserID ${userIdFromToken} | Placa ${placa} | VagaID ${vagaId}`);
    if (!userIdFromToken) {
        console.error("[API /reservar] ERRO CRÍTICO: userIdFromToken é nulo ou indefinido.");
        return res.status(500).json({ message: "Erro interno: Falha na identificação do usuário." });
    }
    const veiculoDoUsuario = await Veiculo.findOne({ where: { placa: placa, user_id: userIdFromToken } });
    if (!veiculoDoUsuario) {
      console.log(`[API /reservar] FALHA Val1: Placa ${placa} não pertence ao UserID ${userIdFromToken} ou não cadastrada.`);
      const veiculoExiste = await Veiculo.findOne({ where: { placa: placa } });
      if (veiculoExiste) {
        return res.status(403).json({ message: `A placa ${placa} está associada a outro usuário.` });
      }
      return res.status(404).json({ message: `Veículo com placa ${placa} não encontrado em seus registros.` });
    }
    console.log(`[API /reservar] SUCESSO Val1: Placa ${placa} pertence ao UserID ${userIdFromToken}.`);
    const outraVagaComMesmaPlaca = await Vaga.findOne({ where: { placa: placa, ocupada: true, id: { [Op.ne]: vagaId } } });
    if (outraVagaComMesmaPlaca) {
      console.log(`[API /reservar] FALHA Val2: Placa ${placa} já ocupa Vaga ${outraVagaComMesmaPlaca.nome}.`);
      return res.status(409).json({ message: `Veículo ${placa} já utiliza a vaga ${outraVagaComMesmaPlaca.nome}.` });
    }
    console.log(`[API /reservar] SUCESSO Val2: Placa ${placa} não está em uso em outra vaga.`);
    const vagaAlvo = await Vaga.findByPk(vagaId);
    if (!vagaAlvo) {
      return res.status(404).json({ message: 'A vaga que você tentou reservar não existe.' });
    }
    console.log(`[API /reservar] SUCESSO Val3: Vaga alvo ${vagaAlvo.nome} encontrada.`);
    if (vagaAlvo.ocupada) {
      if (vagaAlvo.placa === placa) {
        return res.status(409).json({ message: `Vaga ${vagaAlvo.nome} já está reservada para ${placa}.` });
      }
      return res.status(400).json({ message: `Vaga ${vagaAlvo.nome} já está ocupada por ${vagaAlvo.placa}.` });
    }
    console.log(`[API /reservar] SUCESSO Val4: Vaga ${vagaAlvo.nome} está disponível.`);
    vagaAlvo.ocupada = true;
    vagaAlvo.placa = placa;
    await vagaAlvo.save();
    console.log(`[API /reservar] SUCESSO FINAL: Vaga ${vagaAlvo.nome} reservada para ${placa}.`);
    res.status(200).json({ message: `Vaga ${vagaAlvo.nome} reservada com sucesso para ${placa}!`, vaga: vagaAlvo });
  } catch (error) {
    console.error("[API /reservar] ERRO GERAL NA ROTA:", error);
    res.status(500).json({ message: 'Erro interno ao processar sua reserva.' });
  }
});

app.post('/api/vagas/:id/liberar', authenticateJWT, async (req, res) => { /* ... Sua lógica de liberar vaga ... */ });

// Rota TEMPORÁRIA para resetar vagas para apresentação (REMOVER OU PROTEGER DEPOIS)
app.post('/api/vagas/reset-para-apresentacao-agora', async (req, res) => {
  console.warn("[API RESET APRESENTAÇÃO] ROTA DE RESET ACIONADA!");
  try {
    const [numberOfAffectedRows] = await Vaga.update(
      { ocupada: false, placa: null },
      { where: {} }
    );
    const message = `${numberOfAffectedRows} vagas foram resetadas para o estado inicial.`;
    console.log(message);
    res.status(200).json({ message });
  } catch (error) {
    console.error("[API RESET APRESENTAÇÃO] Erro ao resetar vagas:", error);
    res.status(500).json({ message: "Erro ao resetar vagas para apresentação." });
  }
});

// Middleware de tratamento de erros global
app.use((err, req, res, next) => {
  console.error("------------------------------------");
  console.error("ERRO NÃO TRATADO NA APLICAÇÃO:", err.message);
  console.error("Rota:", req.method, req.originalUrl);
  if (err.message.includes("não é permitida por CORS")) { // Tratamento específico para o erro de CORS
      return res.status(403).json({ message: err.message });
  }
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Token inválido ou ausente.' });
  }
  console.error(err.stack); // Logar o stack completo para outros erros
  res.status(500).json({ message: 'Ocorreu um erro inesperado no servidor.' });
});


const port = process.env.PORT || 3000;

async function createInitialVagas() {
  try {
    const count = await Vaga.count();
    if (count === 0) {
      const vagasParaCriar = [];
      for (let i = 1; i <= 15; i++) {
        vagasParaCriar.push({ nome: `Vaga ${i}`, ocupada: false });
      }
      await Vaga.bulkCreate(vagasParaCriar);
      console.log('15 vagas iniciais criadas com sucesso.');
    } else {
      console.log(`${count} vagas já existem. Nenhuma vaga inicial nova criada.`);
    }
  } catch (error) {
    console.error("Erro ao criar vagas iniciais:", error);
  }
}

async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('CONECTADO AO BANCO DE DADOS COM SUCESSO!');

    console.log('Sincronizando modelos com o banco de dados (criando tabelas se não existirem)...');
    // Usando sync() sem opções para criar tabelas faltantes sem alterar/apagar as existentes.
    // Para desenvolvimento mais ativo, { alter: true } pode ser útil, mas use com cautela.
    await sequelize.sync(); // <<--- ALTERAÇÃO AQUI
    console.log('Modelos sincronizados com o banco de dados.');

    await createInitialVagas();

    // Se você quer resetar as vagas toda vez que a API inicia para a apresentação (controlado por .env):
    if (process.env.RESET_VAGAS_ON_STARTUP === 'true') {
        console.warn("[API STARTUP RESET] Resetando todas as vagas para apresentação...");
        await Vaga.update({ ocupada: false, placa: null }, { where: {} });
        console.log("[API STARTUP RESET] Vagas resetadas no início.");
    }

    app.listen(port, () => {
      console.log(`Servidor rodando na porta ${port} em modo ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error('ERRO AO INICIAR SERVIDOR OU CONECTAR/SINCRONIZAR DB:', err);
    process.exit(1);
  }
}

startServer();