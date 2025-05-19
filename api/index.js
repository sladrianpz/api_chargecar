require('dotenv').config(); // Para carregar as variáveis de ambiente (apenas uma vez)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize'); // Importa Sequelize e DataTypes aqui
const { body, validationResult } = require('express-validator');

// Criando o servidor Express
const app = express();

// --- Configuração do Sequelize e Conexão ---
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: console.log, // Mantenha para depuração por enquanto
  // dialectOptions: { // Descomente e configure se a DATABASE_URL sozinha não for suficiente para SSL
  //   ssl: {
  //     require: true,
  //     rejectUnauthorized: true
  //   }
  // }
});

// --- Definição dos Modelos ---
// É bom definir os modelos antes de tentar sincronizar ou autenticar,
// embora a autenticação funcione sem os modelos definidos.
const User = sequelize.define('User', {
  nome: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  senha: { type: DataTypes.STRING, allowNull: false },
}, { tableName: 'user', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

const Veiculo = sequelize.define('Veiculo', {
  placa: { type: DataTypes.STRING(7), allowNull: false },
  cor: { type: DataTypes.STRING(30), allowNull: false },
  modelo: { type: DataTypes.STRING(40), allowNull: false },
  marca: { type: DataTypes.STRING(40), allowNull: false },
  tipo: { type: DataTypes.STRING(50) },
}, { tableName: 'veiculo', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

// Relacionamento entre User e Veiculo
User.hasMany(Veiculo, { foreignKey: 'user_id' });
Veiculo.belongsTo(User, { foreignKey: 'user_id' });


// --- Middlewares do Express ---
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:8081', // Substitua pelo endereço do seu frontend
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Middleware de autenticação JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Acesso negado');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Token inválido');
    req.user = user;
    next();
  });
};

// --- Rotas Express ---
app.post('/register', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { nome, email, senha } = req.body;
    const userExists = await User.findOne({ where: { email } });
    if (userExists) {
      return res.status(400).send('Usuário já existe');
    }
    const hashedPassword = await bcrypt.hash(senha, 10);
    await User.create({ nome, email, senha: hashedPassword });
    res.status(201).send('Usuário cadastrado com sucesso!');
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).send("Erro ao registrar usuário.");
  }
});

app.post('/login', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha inválida'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { email, senha } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).send('Usuário não encontrado');
    }
    const validPassword = await bcrypt.compare(senha, user.senha);
    if (!validPassword) {
      return res.status(400).send('Senha incorreta');
    }
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.send({ message: 'Login bem-sucedido!', token });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).send("Erro ao fazer login.");
  }
});

app.post('/add-vehicle', authenticateJWT, [
  body('placa').isLength({ min: 7, max: 7 }).withMessage('Placa inválida'),
  body('modelo').not().isEmpty().withMessage('Modelo é obrigatório'),
  body('marca').not().isEmpty().withMessage('Marca é obrigatória'),
  body('cor').not().isEmpty().withMessage('Cor é obrigatória'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { placa, modelo, marca, cor } = req.body;
    const vehicleExists = await Veiculo.findOne({ where: { placa } });
    if (vehicleExists) {
      return res.status(400).send('Veículo já cadastrado');
    }
    await Veiculo.create({ placa, modelo, marca, cor, user_id: req.user.userId });
    res.status(201).send('Veículo cadastrado com sucesso');
  } catch (error) {
    console.error("Erro ao adicionar veículo:", error);
    res.status(500).send("Erro ao adicionar veículo.");
  }
});

// Gerenciamento de erros Express (deve ser um dos últimos middlewares)
app.use((err, req, res, next) => {
  console.error("Erro não tratado na rota:", err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

// --- Inicialização do Servidor e Sincronização com DB ---
const port = process.env.PORT || 3000;

async function startServer() {
  try {
    await sequelize.authenticate(); // Testar a conexão
    console.log('CONECTADO AO TIDB CLOUD (MySQL Protocol) COM SUCESSO!');

    // Sincronizar modelos. Cuidado com 'force: true' em produção!
    // { alter: true } é geralmente seguro para desenvolvimento/staging.
    // Para produção, considere usar migrações.
    await sequelize.sync({ alter: true }); 
    console.log('Modelos sincronizados com o banco de dados.');

    app.listen(port, () => {
      console.log(`Servidor rodando na porta ${port}`);
    });
  } catch (err) {
    console.error('ERRO AO INICIAR O SERVIDOR OU CONECTAR/SINCRONIZAR COM O DB:', err);
    process.exit(1); // Saia se houver um erro crítico na inicialização
  }
}

startServer();