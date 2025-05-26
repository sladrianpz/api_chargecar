require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 3000; // Defina a porta aqui

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: process.env.NODE_ENV === 'development' ? msg => console.log('[SEQUELIZE]', msg) : false, // Log SQL em DEV
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? {
      require: true,
      rejectUnauthorized: true, // Importante para Render com SSL
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

const allowedOrigins = ['http://localhost:8081', 'http://localhost:3000']; // Adicione a URL do seu Expo Web se estiver usando
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}
// Adicione a URL do Render Preview se estiver usando previews
if (process.env.RENDER_PREVIEW_URL) {
    allowedOrigins.push(process.env.RENDER_PREVIEW_URL);
}


app.use(cors({
  origin: function (origin, callback) {
    console.log("[CORS] Checando origem:", origin);
    if (!origin || allowedOrigins.includes(origin)) {
      console.log("[CORS] Origem permitida:", origin);
      callback(null, true);
    } else {
      console.error(`[CORS] Origem BLOQUEADA: ${origin}. Origens permitidas: ${allowedOrigins.join(', ')}`);
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

// Rota de teste simples
app.get('/', (req, res) => {
  res.status(200).send('API ChargeCar está no ar! Bem-vindo!');
});

// Suas outras rotas (/register, /login, /add-vehicle, etc.) devem vir aqui
// Exemplo:
// app.post('/register', ..., async (req, res) => { /* ... */ });
// app.post('/login', ..., async (req, res) => { /* ... */ });


// Rota para listar vagas
app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    console.log(`[API /api/vagas GET] Iniciando busca de vagas. UserID: ${req.user?.userId}`);
    const vagas = await Vaga.findAll({
        order: [['nome', 'ASC']]
    });
    console.log(`[API /api/vagas GET] Consulta ao banco realizada. Vagas encontradas: ${vagas?.length}`);
    if (!vagas) { // Verificação extra, findAll geralmente retorna array vazio se nada for encontrado
        console.warn("[API /api/vagas GET] Vaga.findAll retornou nulo/undefined, o que é inesperado.");
        return res.status(200).json([]); // Retorna array vazio como fallback seguro
    }
    res.status(200).json(vagas);
  } catch (error) {
    console.error(`[API /api/vagas GET] ERRO CRÍTICO AO LISTAR VAGAS:`);
    console.error(`[API /api/vagas GET] Mensagem: ${error.message}`);
    console.error(`[API /api/vagas GET] Stack:`, error.stack);
    if (error.original) {
        console.error(`[API /api/vagas GET] Erro Original do DB:`, error.original);
    }
    res.status(500).json({
      message: "Ocorreu um erro grave ao buscar as vagas no servidor. Por favor, tente novamente mais tarde.",
      // Em desenvolvimento, você pode querer enviar mais detalhes do erro:
      // errorDetails: process.env.NODE_ENV === 'development' ? error.message : undefined,
      // errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    });
  }
});

// Suas outras rotas (/api/vagas/:id/reservar, /api/vagas/reset-para-apresentacao-agora, etc.)
// Exemplo:
// app.post('/api/vagas/:id/reservar', ..., async (req, res) => { /* ... */ });


// Middleware de tratamento de erros global
app.use((err, req, res, next) => {
  console.error("------------------------------------");
  console.error("MIDDLEWARE DE ERRO GLOBAL CAPTUROU:");
  console.error("Mensagem:", err.message);
  console.error("Rota:", req.method, req.originalUrl);

  if (err.message.includes("não é permitida por CORS")) {
      return res.status(403).json({ message: err.message });
  }
  if (err.name === 'UnauthorizedError') { // Erro de JWT não pego pelo authenticateJWT
    return res.status(401).json({ message: 'Autenticação falhou (token inválido/ausente).' });
  }
  // Para outros erros, logar o stack e retornar um erro genérico
  console.error("Stack:", err.stack);
  res.status(500).json({ message: 'Ocorreu um erro inesperado no servidor.' });
});

// Funções de inicialização
async function createInitialVagas() {
  try {
    // Verifica se a tabela 'vaga' existe antes de tentar contar ou criar
    // O Sequelize pode lançar um erro se a tabela não existir ao tentar Vaga.count()
    // Uma forma mais robusta seria verificar o schema, mas para simplificar,
    // confiaremos que o sync() criou a tabela. Se falhar, o catch aqui pegará.
    const count = await Vaga.count();
    if (count === 0) {
      const vagasParaCriar = [];
      for (let i = 1; i <= 15; i++) {
        vagasParaCriar.push({ nome: `Vaga ${i}` }); // ocupada e placa terão seus defaults
      }
      await Vaga.bulkCreate(vagasParaCriar);
      console.log('[API STARTUP] 15 vagas iniciais criadas com sucesso.');
    } else {
      console.log(`[API STARTUP] ${count} vagas já existem. Nenhuma vaga inicial nova criada.`);
    }
  } catch (error) {
    console.error("[API STARTUP] Erro ao verificar/criar vagas iniciais. Isso pode acontecer se a tabela 'vaga' não foi criada corretamente pelo sync ou se há outro problema de banco:", error.message);
    // Não vamos parar a aplicação por isso, mas é um aviso importante.
  }
}

async function startServer() {
  try {
    console.log('[API STARTUP] Iniciando servidor...');
    console.log(`[API STARTUP] DATABASE_URL: ${process.env.DATABASE_URL ? 'Definida' : 'NÃO DEFINIDA!'}`);
    console.log(`[API STARTUP] DB_SSL: ${process.env.DB_SSL}`);
    console.log(`[API STARTUP] JWT_SECRET: ${process.env.JWT_SECRET ? 'Definido' : 'NÃO DEFINIDO!'}`);

    await sequelize.authenticate();
    console.log('[API STARTUP] CONECTADO AO BANCO DE DADOS COM SUCESSO!');

    console.log('[API STARTUP] Sincronizando modelos com o banco de dados...');
    // Usar { alter: true } durante o desenvolvimento para que as tabelas sejam ajustadas
    // se você mudar os modelos. Em produção, use migrações.
    // Se você APAGOU a tabela, { alter: true } ou sync() sem opções deve recriá-la.
    await sequelize.sync({ alter: true }); // <<--- FOCO AQUI
    console.log('[API STARTUP] Modelos sincronizados com o banco de dados.');

    await createInitialVagas();

    if (process.env.RESET_VAGAS_ON_STARTUP === 'true') {
        console.warn("[API STARTUP RESET] Resetando todas as vagas devido à variável de ambiente...");
        await Vaga.update({ ocupada: false, placa: null }, { where: {} });
        console.log("[API STARTUP RESET] Vagas resetadas no início.");
    }

    app.listen(port, () => {
      console.log(`[API STARTUP] Servidor rodando na porta ${port} em modo ${process.env.NODE_ENV || 'development'}`);
      console.log(`[API STARTUP] API pronta e escutando em http://localhost:${port} (localmente) ou na URL do Render.`);
    });

  } catch (err) {
    console.error('[API STARTUP] ERRO CRÍTICO AO INICIAR SERVIDOR:');
    console.error('Mensagem:', err.message);
    console.error('Stack:', err.stack);
    if (err.original) {
        console.error('Erro Original do Driver (pode indicar problema de conexão/credenciais):', err.original);
    }
    process.exit(1);
  }
}

// Adicione suas outras rotas (/register, /login, etc.) AQUI, antes de chamar startServer()
// Exemplo (coloque suas rotas completas aqui):
app.post('/register', [body('nome').notEmpty(), body('email').isEmail(), body('senha').isLength({min:6})], async (req, res) => { /* ... sua lógica ... */});
app.post('/login', [body('email').isEmail(), body('senha').notEmpty()], async (req, res) => { /* ... sua lógica ... */});
app.post('/add-vehicle', authenticateJWT, [/* validações */], async (req, res) => { /* ... sua lógica ... */});
app.post('/api/vagas/:id/reservar', authenticateJWT, [/* validações */], async (req, res) => { /* ... sua lógica completa da rota de reserva ... */});
// etc.

startServer();