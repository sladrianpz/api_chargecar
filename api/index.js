require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const { body, validationResult } = require('express-validator');

const app = express();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: console.log,
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: true,
    }
  }
});

// Modelos

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

User.hasMany(Veiculo, { foreignKey: 'user_id' });
Veiculo.belongsTo(User, { foreignKey: 'user_id' });

// Modelo para vagas de carregamento
const Vaga = sequelize.define('Vaga', {
  nome: { type: DataTypes.STRING, allowNull: false },          // Ex: "Vaga 1"
  ocupada: { type: DataTypes.BOOLEAN, defaultValue: false },   // Status da vaga
  placa: { type: DataTypes.STRING(7), allowNull: true },       // Placa do veículo que reservou
}, { tableName: 'vaga', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

// Middlewares
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:8081',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Middleware JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Acesso negado');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Token inválido');
    req.user = user;
    next();
  });
};

// Rotas

// Registro de usuário
app.post('/register', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { nome, email, senha } = req.body;
    const userExists = await User.findOne({ where: { email } });
    if (userExists) return res.status(400).send('Usuário já existe');

    const hashedPassword = await bcrypt.hash(senha, 10);
    await User.create({ nome, email, senha: hashedPassword });
    res.status(201).send('Usuário cadastrado com sucesso!');
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).send("Erro ao registrar usuário.");
  }
});

// Login
app.post('/login', [
  body('email').isEmail().withMessage('Email inválido'),
  body('senha').isLength({ min: 6 }).withMessage('Senha inválida'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email, senha } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).send('Usuário não encontrado');

    const validPassword = await bcrypt.compare(senha, user.senha);
    if (!validPassword) return res.status(400).send('Senha incorreta');

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.send({ message: 'Login bem-sucedido!', token });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).send("Erro ao fazer login.");
  }
});

// Adicionar veículo
app.post('/add-vehicle', authenticateJWT, [
  body('placa').isLength({ min: 7, max: 7 }).withMessage('Placa inválida'),
  body('modelo').not().isEmpty().withMessage('Modelo é obrigatório'),
  body('marca').not().isEmpty().withMessage('Marca é obrigatória'),
  body('cor').not().isEmpty().withMessage('Cor é obrigatória'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { placa, modelo, marca, cor } = req.body;
    const vehicleExists = await Veiculo.findOne({ where: { placa } });
    if (vehicleExists) return res.status(400).send('Veículo já cadastrado');

    await Veiculo.create({ placa, modelo, marca, cor, user_id: req.user.userId });
    res.status(201).send('Veículo cadastrado com sucesso');
  } catch (error) {
    console.error("Erro ao adicionar veículo:", error);
    res.status(500).send("Erro ao adicionar veículo.");
  }
});

// Listar vagas (após login)
app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    const vagas = await Vaga.findAll();
    res.json(vagas);
  } catch (error) {
    console.error("Erro ao listar vagas:", error);
    res.status(500).send("Erro ao listar vagas");
  }
});

// Reservar vaga por id
app.post('/api/vagas/:id/reservar', authenticateJWT, [
  body('placa').isLength({ min: 7, max: 7 }).withMessage('Placa inválida'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const vaga = await Vaga.findByPk(req.params.id);
    if (!vaga) return res.status(404).send("Vaga não encontrada");
    if (vaga.ocupada) return res.status(400).send("Vaga já reservada");

    const { placa } = req.body;

    vaga.ocupada = true;
    vaga.placa = placa.toUpperCase();
    await vaga.save();

    res.json(vaga);
  } catch (error) {
    console.error("Erro ao reservar vaga:", error);
    res.status(500).send("Erro ao reservar vaga");
  }
});

// Middleware de erros (último middleware)
app.use((err, req, res, next) => {
  console.error("Erro não tratado na rota:", err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

const port = process.env.PORT || 3000;

// Função para criar as vagas iniciais (15 vagas)
async function createInitialVagas() {
  const count = await Vaga.count();
  if (count === 0) {
    for (let i = 1; i <= 15; i++) {
      await Vaga.create({ nome: `Vaga ${i}`, ocupada: false });
    }
    console.log('Vagas iniciais criadas');
  }
}

async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('CONECTADO AO BANCO COM SUCESSO!');

    await sequelize.sync();
    console.log('Modelos sincronizados.');

    await createInitialVagas();

    app.listen(port, () => {
      console.log(`Servidor rodando na porta ${port}`);
    });
  } catch (err) {
    console.error('Erro ao iniciar servidor ou conectar/sincronizar DB:', err);
    process.exit(1);
  }
}

startServer();
