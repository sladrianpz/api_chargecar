require('dotenv').config();  // Para carregar as variáveis de ambiente
const express = require('express');
const cors = require('cors');  // Importando o CORS
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const { body, validationResult } = require('express-validator');

// Criando o servidor Express
const app = express();

require('dotenv').config();
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  // NÃO adicione 'dialectOptions.ssl' aqui se a DATABASE_URL já cuida disso.
  // Se você adicionar, ele pode sobrescrever ou conflitar.
  logging: console.log, // Mantenha para depuração por enquanto
});

sequelize.authenticate()
  .then(() => {
    console.log('CONECTADO AO TIDB CLOUD (MySQL Protocol) COM SUCESSO!');
  })
  .catch(err => {
    console.error('ERRO AO CONECTAR AO TIDB CLOUD (TENTATIVA COM URL):', err);
  });

module.exports = sequelize;
// Testar a conexão com o banco de dados
sequelize.authenticate()
  .then(() => console.log('Conectado ao MySQL'))
  .catch(err => console.error('Erro ao conectar: ' + err));

// Definindo o modelo de Usuário
const User = sequelize.define('User', {
  nome: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  senha: {
    type: DataTypes.STRING,
    allowNull: false,
  },
}, {
  tableName: 'user',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
});

// Definindo o modelo de Veículo
const Veiculo = sequelize.define('Veiculo', {
  placa: {
    type: DataTypes.STRING(7),
    allowNull: false,
  },
  cor: {
    type: DataTypes.STRING(30),
    allowNull: false,
  },
  modelo: {
    type: DataTypes.STRING(40),
    allowNull: false,
  },
  marca: {
    type: DataTypes.STRING(40),
    allowNull: false,
  },
  tipo: {
    type: DataTypes.STRING(50),
  },
}, {
  tableName: 'veiculo',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: 'updated_at',
});

// Relacionamento entre User e Veiculo
User.hasMany(Veiculo, { foreignKey: 'user_id' });
Veiculo.belongsTo(User, { foreignKey: 'user_id' });

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

// Middleware para aceitar JSON
app.use(express.json());

// Configurar CORS para permitir a origem específica
app.use(cors({
  origin: 'http://localhost:8081',  // Substitua pelo endereço do seu frontend
  methods: ['GET', 'POST'],         // Métodos permitidos
  allowedHeaders: ['Content-Type', 'Authorization'],  // Cabeçalhos permitidos
}));

// Rota para cadastro de novos usuários
app.post('/register', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { nome, email, senha } = req.body;
  
  // Verificar se o usuário já existe
  const userExists = await User.findOne({ where: { email } });
  if (userExists) {
    return res.status(400).send('Usuário já existe');
  }

  // Criptografar a senha
  const hashedPassword = await bcrypt.hash(senha, 10);

  // Criar um novo usuário
  const user = await User.create({ nome, email, senha: hashedPassword });
  
  res.status(201).send('Usuário cadastrado com sucesso!');
});

// Rota para login e validação de dados
app.post('/login', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha inválida'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, senha } = req.body;
  
  // Buscar usuário no banco de dados
  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(400).send('Usuário não encontrado');
  }

  // Validar a senha
  const validPassword = await bcrypt.compare(senha, user.senha);
  if (!validPassword) {
    return res.status(400).send('Senha incorreta');
  }

  // Gerar token JWT
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.send({ message: 'Login bem-sucedido!', token });
});

// Rota para adicionar veículos (exemplo de funcionalidade autenticada)
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

  const { placa, modelo, marca, cor } = req.body;

  // Verificar se o veículo já existe
  const vehicleExists = await Veiculo.findOne({ where: { placa } });
  if (vehicleExists) {
    return res.status(400).send('Veículo já cadastrado');
  }

  // Criar novo veículo
  const veiculo = await Veiculo.create({
    placa, modelo, marca, cor, user_id: req.user.userId
  });
  
  res.status(201).send('Veículo cadastrado com sucesso');
});

// Gerenciamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

// Iniciar o servidor
const port = process.env.PORT ||3000;
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
