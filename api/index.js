require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize'); // Adicionado Op
const { body, validationResult } = require('express-validator');

const app = express();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  // logging: console.log, // Pode comentar ou remover para produção para não poluir os logs
  logging: process.env.NODE_ENV === 'development' ? console.log : false, // Log apenas em desenvolvimento
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? { // Torna o SSL configurável via .env
      require: true,
      rejectUnauthorized: true, // Mantenha true para produção com CAs válidos
    } : false,
  }
});

// Modelos
const User = sequelize.define('User', {
  nome: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  senha: { type: DataTypes.STRING, allowNull: false },
}, { tableName: 'user', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

const Veiculo = sequelize.define('Veiculo', {
  placa: { type: DataTypes.STRING(7), allowNull: false, unique: true }, // Placa deve ser única
  cor: { type: DataTypes.STRING(30), allowNull: false },
  modelo: { type: DataTypes.STRING(40), allowNull: false },
  marca: { type: DataTypes.STRING(40), allowNull: false },
  tipo: { type: DataTypes.STRING(50) },
  // user_id já é adicionado pela associação abaixo
}, { tableName: 'veiculo', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

User.hasMany(Veiculo, { foreignKey: 'user_id', allowNull: false }); // Garante que user_id não seja nulo
Veiculo.belongsTo(User, { foreignKey: 'user_id', allowNull: false });

const Vaga = sequelize.define('Vaga', {
  nome: { type: DataTypes.STRING, allowNull: false, unique: true }, // Nome da vaga deve ser único
  ocupada: { type: DataTypes.BOOLEAN, defaultValue: false },
  placa: { type: DataTypes.STRING(7), allowNull: true },
  // Opcional: Poderia adicionar user_id aqui também para saber quem reservou
  // user_id_reserva: {
  //   type: DataTypes.INTEGER,
  //   allowNull: true,
  //   references: {
  //     model: User,
  //     key: 'id'
  //   }
  // }
}, { tableName: 'vaga', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

// Middlewares
app.use(express.json());

// Configuração CORS mais flexível para desenvolvimento e produção
const allowedOrigins = ['http://localhost:8081', 'http://localhost:3000']; // Adicione aqui a URL do seu app publicado
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    // Permite requisições sem 'origin' (ex: Postman, curl) ou se a origem estiver na lista
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Adicione outros métodos se necessário
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Se você usar cookies/sessões no futuro
}));

// Middleware JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Acesso negado. Token não fornecido ou mal formatado.' });
  }
  const token = authHeader.replace('Bearer ', '');

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => { // 'user' é geralmente chamado de 'decodedToken' ou 'payload'
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expirado.' });
      }
      return res.status(403).json({ message: 'Token inválido.' });
    }
    req.user = decodedToken; // Geralmente o payload do token (ex: { userId: 1, ... })
    next();
  });
};

// --- ROTAS ---

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
    if (userExists) return res.status(409).json({ message: 'Este e-mail já está cadastrado.' }); // 409 Conflict

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
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas.' }); // 401 Unauthorized

    const validPassword = await bcrypt.compare(senha, user.senha);
    if (!validPassword) return res.status(401).json({ message: 'Credenciais inválidas.' }); // 401 Unauthorized

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
    const userId = req.user.userId; // Obtido do token

    // Verifica se a placa já existe no sistema (independente do usuário)
    const vehicleExistsGlobal = await Veiculo.findOne({ where: { placa } });
    if (vehicleExistsGlobal) {
        // Se o veículo existe e pertence a outro usuário
        if (vehicleExistsGlobal.user_id !== userId) {
            return res.status(409).json({ message: `Veículo com placa ${placa} já cadastrado por outro usuário.` });
        }
        // Se o veículo existe e já pertence ao usuário atual (tentativa de re-cadastro)
        return res.status(409).json({ message: `Você já cadastrou o veículo com placa ${placa}.` });
    }

    const newVehicle = await Veiculo.create({
      placa,
      modelo,
      marca,
      cor,
      tipo: tipo || null, // Define como null se não fornecido
      user_id: userId
    });
    res.status(201).json({ message: 'Veículo cadastrado com sucesso!', veiculo: newVehicle });
  } catch (error) {
    console.error("Erro ao adicionar veículo:", error);
    if (error.name === 'SequelizeUniqueConstraintError') { // Trata erro de placa duplicada do DB
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
    if (!veiculos || veiculos.length === 0) {
      return res.status(200).json([]); // Retorna array vazio se não tiver veículos
    }
    res.status(200).json(veiculos);
  } catch (error) {
    console.error("Erro ao listar veículos do usuário:", error);
    res.status(500).json({ message: "Erro interno ao buscar seus veículos." });
  }
});


// Listar vagas
app.get('/api/vagas', authenticateJWT, async (req, res) => {
  try {
    const vagas = await Vaga.findAll({
        order: [['nome', 'ASC']] // Ordena as vagas pelo nome
    });
    res.status(200).json(vagas);
  } catch (error) {
    console.error("Erro ao listar vagas:", error);
    res.status(500).json({ message: "Erro interno ao listar vagas." });
  }
});

// Reservar vaga por id
app.post('/api/vagas/:id/reservar', authenticateJWT, [
  body('placa').trim().toUpperCase().isLength({ min: 7, max: 7 }).withMessage('Placa inválida (deve ter 7 caracteres).'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const vagaId = req.params.id;
    const { placa } = req.body; // Placa já vem validada (tamanho, trim, uppercase)
    const userId = req.user.userId;

    // 1. Verificar se o veículo com a placa informada existe E pertence ao usuário logado
    const veiculoDoUsuario = await Veiculo.findOne({
      where: {
        placa: placa,
        user_id: userId,
      },
    });

    if (!veiculoDoUsuario) {
      // Para dar uma mensagem mais específica, podemos verificar se a placa existe mas não é do usuário
      const veiculoExisteOutroUsuario = await Veiculo.findOne({ where: { placa }});
      if (veiculoExisteOutroUsuario) {
          return res.status(403).json({ message: `A placa ${placa} está registrada para outro usuário.` });
      }
      return res.status(404).json({ message: `Veículo com placa ${placa} não encontrado em seus registros. Cadastre o veículo primeiro.` });
    }

    // 2. Verificar se a vaga existe
    const vaga = await Vaga.findByPk(vagaId);
    if (!vaga) {
      return res.status(404).json({ message: 'Vaga não encontrada.' });
    }

    // 3. Verificar se a vaga já está ocupada
    if (vaga.ocupada) {
      // Se já está ocupada pela MESMA placa E (opcionalmente) pelo mesmo usuário, pode ser um erro ou tentativa de re-reserva
      if (vaga.placa === placa) { // Adicionar && vaga.user_id_reserva === userId se tiver esse campo
        return res.status(409).json({ message: `Vaga ${vaga.nome} já está reservada para o veículo ${placa}.` }); // 409 Conflict
      }
      return res.status(400).json({ message: `Vaga ${vaga.nome} já está ocupada por outro veículo.` });
    }

    // 4. Reservar a vaga
    vaga.ocupada = true;
    vaga.placa = placa;
    // if (vaga.user_id_reserva !== undefined) vaga.user_id_reserva = userId; // Se adicionar user_id_reserva
    await vaga.save();

    res.status(200).json({
      message: `Vaga ${vaga.nome} reservada com sucesso para o veículo ${placa}!`,
      vaga: { // Retorna os detalhes da vaga atualizada
        id: vaga.id,
        nome: vaga.nome,
        ocupada: vaga.ocupada,
        placa: vaga.placa,
      },
    });

  } catch (error) {
    console.error("Erro ao reservar vaga:", error);
    res.status(500).json({ message: 'Erro interno ao tentar reservar a vaga.' });
  }
});

// Futura rota para liberar uma vaga (exemplo)
app.post('/api/vagas/:id/liberar', authenticateJWT, async (req, res) => {
    try {
        const vagaId = req.params.id;
        const userId = req.user.userId;

        const vaga = await Vaga.findByPk(vagaId);
        if (!vaga) {
            return res.status(404).json({ message: "Vaga não encontrada." });
        }

        if (!vaga.ocupada) {
            return res.status(400).json({ message: `Vaga ${vaga.nome} já está livre.` });
        }

        // Opcional: Verificar se o usuário que está liberando é o mesmo que reservou
        // ou se tem permissão para liberar qualquer vaga.
        // Por simplicidade, vamos assumir que o veículo precisa ser do usuário.
        if (vaga.placa) {
            const veiculoNaVaga = await Veiculo.findOne({ where: { placa: vaga.placa, user_id: userId }});
            if (!veiculoNaVaga) {
                return res.status(403).json({ message: `Você não pode liberar esta vaga pois ela não está reservada para um veículo seu.`})
            }
        }
        // Se não houver placa ou se a validação acima passar:
        vaga.ocupada = false;
        vaga.placa = null;
        // if (vaga.user_id_reserva !== undefined) vaga.user_id_reserva = null;
        await vaga.save();

        res.status(200).json({ message: `Vaga ${vaga.nome} liberada com sucesso.`, vaga });

    } catch (error) {
        console.error("Erro ao liberar vaga:", error);
        res.status(500).json({ message: "Erro interno ao tentar liberar a vaga." });
    }
});


// Middleware de tratamento de erros global (deve ser o último)
app.use((err, req, res, next) => {
  console.error("------------------------------------");
  console.error("ERRO NÃO TRATADO NA APLICAÇÃO:");
  console.error("Rota:", req.method, req.originalUrl);
  if (req.body && Object.keys(req.body).length > 0) console.error("Body:", req.body);
  if (req.params && Object.keys(req.params).length > 0) console.error("Params:", req.params);
  if (req.query && Object.keys(req.query).length > 0) console.error("Query:", req.query);
  console.error(err.stack || err);
  console.error("------------------------------------");

  if (err.name === 'UnauthorizedError') { // Exemplo de erro JWT não tratado pelo authenticateJWT
    return res.status(401).json({ message: 'Token inválido ou ausente.' });
  }
  // Se o erro for de CORS, ele já foi tratado e não deveria chegar aqui
  // mas caso aconteça:
  if (err.message === 'Not allowed by CORS') {
    return res.status(415).json({ message: err.message }); // Unsupported Media Type pode ser um código apropriado, ou 403
  }

  res.status(500).json({ message: 'Ocorreu um erro inesperado no servidor.' });
});


const port = process.env.PORT || 3000;

// Função para criar as vagas iniciais (15 vagas)
async function createInitialVagas() {
  try {
    const count = await Vaga.count();
    if (count === 0) {
      const vagasParaCriar = [];
      for (let i = 1; i <= 15; i++) {
        vagasParaCriar.push({ nome: `Vaga ${i}`, ocupada: false });
      }
      await Vaga.bulkCreate(vagasParaCriar); // Mais eficiente para múltiplas inserções
      console.log('15 vagas iniciais criadas com sucesso.');
    } else {
      console.log(`${count} vagas já existem no banco de dados. Nenhuma nova vaga inicial criada.`);
    }
  } catch (error) {
    console.error("Erro ao criar vagas iniciais:", error);
  }
}

async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('CONECTADO AO BANCO DE DADOS COM SUCESSO!');

    // CUIDADO: sequelize.sync({ force: true }) apaga e recria as tabelas. Use com cautela.
    // sequelize.sync({ alter: true }) tenta alterar as tabelas para corresponderem aos modelos. Mais seguro.
    await sequelize.sync({ alter: process.env.NODE_ENV === 'development' }); // alter: true apenas em dev
    console.log('Modelos sincronizados com o banco de dados.');

    await createInitialVagas(); // Cria as vagas se não existirem

    app.listen(port, () => {
      console.log(`Servidor rodando na porta ${port} em modo ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error('ERRO AO INICIAR SERVIDOR OU CONECTAR/SINCRONIZAR DB:', err);
    process.exit(1); // Encerra o processo se não conseguir iniciar
  }
}

startServer();