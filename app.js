// Sistema de Fiscalização de Contratos Públicos
// Aplicativo Principal com Criptografia e Segurança

// ================== CONFIGURAÇÕES GLOBAIS ==================
const APP_CONFIG = {
    version: '1.0.0',
    dbName: 'FiscalizacaoContratosDB',
    dbVersion: 1,
    encryptionKey: 'FiscalizacaoSegura2025!@#$%',
    sessionTimeout: 30 * 60 * 1000, // 30 minutos
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedFileTypes: ['pdf', 'xlsx', 'xls', 'jpg', 'jpeg', 'png']
};

// ================== ESTADO GLOBAL DA APLICAÇÃO ==================
let appState = {
    currentUser: null,
    currentContract: null,
    documents: [],
    inconsistencies: [],
    db: null,
    ocrWorker: null,
    dbInitialized: false
};

// ================== MÓDULO DE CRIPTOGRAFIA ==================
const CryptoModule = {
    // Gerar hash SHA-256 para senhas
    hashPassword(password) {
        return CryptoJS.SHA256(password + APP_CONFIG.encryptionKey).toString();
    },

    // Criptografar dados sensíveis com AES-256
    encryptData(data) {
        try {
            const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), APP_CONFIG.encryptionKey).toString();
            return encrypted;
        } catch (error) {
            console.error('Erro na criptografia:', error);
            return null;
        }
    },

    // Descriptografar dados
    decryptData(encryptedData) {
        try {
            const bytes = CryptoJS.AES.decrypt(encryptedData, APP_CONFIG.encryptionKey);
            const decrypted = bytes.toString(CryptoJS.enc.Utf8);
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Erro na descriptografia:', error);
            return null;
        }
    },

    // Gerar token JWT simulado
    generateToken(user) {
        const header = { typ: 'JWT', alg: 'HS256' };
        const payload = {
            user: user.email,
            profile: user.perfil,
            exp: Date.now() + APP_CONFIG.sessionTimeout
        };
        
        const headerEncoded = btoa(JSON.stringify(header));
        const payloadEncoded = btoa(JSON.stringify(payload));
        const signature = CryptoJS.HmacSHA256(headerEncoded + '.' + payloadEncoded, APP_CONFIG.encryptionKey).toString();
        
        return `${headerEncoded}.${payloadEncoded}.${signature}`;
    },

    // Validar token JWT
    validateToken(token) {
        try {
            const [header, payload, signature] = token.split('.');
            const expectedSignature = CryptoJS.HmacSHA256(header + '.' + payload, APP_CONFIG.encryptionKey).toString();
            
            if (signature !== expectedSignature) return null;
            
            const decodedPayload = JSON.parse(atob(payload));
            if (decodedPayload.exp < Date.now()) return null;
            
            return decodedPayload;
        } catch (error) {
            return null;
        }
    }
};

// ================== MÓDULO DE BANCO DE DADOS ==================
const DatabaseModule = {
    async init() {
        if (appState.dbInitialized && appState.db) {
            console.log('Banco já inicializado, reutilizando conexão');
            return appState.db;
        }

        console.log('Inicializando novo banco de dados...');
        return new Promise((resolve, reject) => {
            // Abrir/criar banco sem deletar dados existentes
            this.createDatabase(resolve, reject);
        });
    },

    createDatabase(resolve, reject) {
        console.log('Criando banco de dados...');
        const request = indexedDB.open(APP_CONFIG.dbName, APP_CONFIG.dbVersion);
        
        request.onerror = (event) => {
            console.error('Erro ao abrir banco:', event.target.error);
            reject(event.target.error);
        };
        
        request.onsuccess = (event) => {
            appState.db = event.target.result;
            appState.dbInitialized = true;
            console.log('✓ Banco de dados conectado');
            resolve(appState.db);
        };
        
        request.onupgradeneeded = (event) => {
            console.log('Atualizando estrutura do banco...');
            const db = event.target.result;
            
            try {
                // Limpar stores existentes se necessário
                const storeNames = ['usuarios', 'contratos', 'documentos', 'inconsistencias', 'regras','aditivos','prorrogacoes'];
                
                storeNames.forEach(storeName => {
                    if (db.objectStoreNames.contains(storeName)) {
                        db.deleteObjectStore(storeName);
                        console.log(`Store ${storeName} removido`);
                    }
                });
                
                // Criar stores
                const usuariosStore = db.createObjectStore('usuarios', { keyPath: 'id', autoIncrement: true });
                usuariosStore.createIndex('email', 'email', { unique: true });
                
                const contratosStore = db.createObjectStore('contratos', { keyPath: 'id', autoIncrement: true });
                contratosStore.createIndex('numero', 'numero', { unique: true });
                
                const documentosStore = db.createObjectStore('documentos', { keyPath: 'id', autoIncrement: true });
                documentosStore.createIndex('contrato_id', 'contrato_id');
                
                db.createObjectStore('inconsistencias', { keyPath: 'id', autoIncrement: true });
                db.createObjectStore('regras', { keyPath: 'id', autoIncrement: true });
                
                console.log('✓ Estrutura do banco criada');
                
            } catch (error) {
                console.error('Erro ao criar estrutura:', error);
                reject(error);
            }
        };
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            const transaction = event.target.transaction;
            
            // Criar estrutura do banco
            if (!db.objectStoreNames.contains('usuarios')) {
                const usuariosStore = db.createObjectStore('usuarios', { keyPath: 'id', autoIncrement: true });
                usuariosStore.createIndex('email', 'email', { unique: true });
            }
            
            if (!db.objectStoreNames.contains('contratos')) {
                const contratosStore = db.createObjectStore('contratos', { keyPath: 'id', autoIncrement: true });
                contratosStore.createIndex('numero', 'numero', { unique: true });
            }
            
            if (!db.objectStoreNames.contains('documentos')) {
                const documentosStore = db.createObjectStore('documentos', { keyPath: 'id', autoIncrement: true });
                documentosStore.createIndex('contrato_id', 'contrato_id');
            }
            
            if (!db.objectStoreNames.contains('inconsistencias')) {
                db.createObjectStore('inconsistencias', { keyPath: 'id', autoIncrement: true });
            }
            
            if (!db.objectStoreNames.contains('regras')) {
                db.createObjectStore('regras', { keyPath: 'id', autoIncrement: true });
            }
            
            // Aguardar transação completar para inserir dados
            transaction.oncomplete = () => {
                console.log('Estrutura criada, inserindo dados iniciais...');
                setTimeout(() => {
                    this.insertInitialData();
                }, 100);
            };
        };
    },

    async insertInitialData() {
        console.log('Inserindo dados iniciais...');
        
        try {
            // Inserir usuários
            const usuarios = [
                { 
                    email: 'admin@orgao.gov.br', 
                    senha_hash: CryptoModule.hashPassword('123456'), 
                    perfil: 'admin', 
                    nome: 'Administrador Sistema' 
                },
                { 
                    email: 'fiscal.admin@orgao.gov.br', 
                    senha_hash: CryptoModule.hashPassword('123456'), 
                    perfil: 'fiscal_administrativo', 
                    nome: 'João Silva - Fiscal Administrativo' 
                },
                { 
                    email: 'fiscal.tecnico@orgao.gov.br', 
                    senha_hash: CryptoModule.hashPassword('123456'), 
                    perfil: 'fiscal_tecnico', 
                    nome: 'Maria Santos - Fiscal Técnico' 
                }
            ];
            
            for (const usuario of usuarios) {
                await this.addToStore('usuarios', usuario);
            }
            console.log('✓ Usuários inseridos');
            
            // Inserir contratos
            const contratos = [
                {
                    numero: '001/2025',
                    objeto: 'Prestação de serviços de limpeza e conservação',
                    empresa_cnpj: '12.345.678/0001-90',
                    empresa_nome: 'Limpeza Total Ltda',
                    vigencia_inicio: '2025-01-01',
                    vigencia_fim: '2025-12-31',
                    valor_mensal: 45000.00
                },
                {
                    numero: '002/2025',
                    objeto: 'Prestação de serviços de segurança patrimonial',
                    empresa_cnpj: '98.765.432/0001-10',
                    empresa_nome: 'Segurança 24h Ltda',
                    vigencia_inicio: '2025-01-15',
                    vigencia_fim: '2026-01-14',
                    valor_mensal: 85000.00
                }
            ];
            
            for (const contrato of contratos) {
                await this.addToStore('contratos', contrato);
            }
            console.log('✓ Contratos inseridos');
            
            // Inserir regras
            const regras = [
                { tipo_regra: 'PRAZO_PAGAMENTO', valor: 5, descricao: 'Pagamento de salários até o 5º dia útil do mês seguinte', ativa: true },
                { tipo_regra: 'PERCENTUAL_FGTS', valor: 8, descricao: 'FGTS deve ser 8% do salário bruto', ativa: true },
                { tipo_regra: 'PERCENTUAL_INSS', valor: 20, descricao: 'INSS Patronal deve ser 20% da folha', ativa: true },
                { tipo_regra: 'SALARIO_MINIMO', valor: 1320, descricao: 'Salário não pode ser inferior ao mínimo nacional', ativa: true }
            ];
            
            for (const regra of regras) {
                await this.addToStore('regras', regra);
            }
            console.log('✓ Regras inseridas');
            
            console.log('✓ Dados iniciais inseridos com sucesso');
            
        } catch (error) {
            console.error('Erro ao inserir dados iniciais:', error);
        }
    },

    async getFromStore(storeName, query = null) {
        if (!appState.dbInitialized || !appState.db) {
            throw new Error('Banco de dados não inicializado');
        }

        return new Promise((resolve, reject) => {
            try {
                const transaction = appState.db.transaction([storeName], 'readonly');
                const store = transaction.objectStore(storeName);
                
                const request = query ? store.get(query) : store.getAll();
                
                request.onsuccess = () => {
                    resolve(request.result);
                };
                
                request.onerror = () => {
                    reject(request.error);
                };
                
                transaction.onerror = () => {
                    reject(transaction.error);
                };
                
            } catch (error) {
                reject(error);
            }
        });
    },

    async addToStore(storeName, data) {
        if (!appState.dbInitialized || !appState.db) {
            throw new Error('Banco de dados não inicializado');
        }

        return new Promise((resolve, reject) => {
            try {
                const transaction = appState.db.transaction([storeName], 'readwrite');
                const store = transaction.objectStore(storeName);
                const request = store.add(data);
                
                request.onsuccess = () => {
                    resolve(request.result);
                };
                
                request.onerror = () => {
                    reject(request.error);
                };
                
            } catch (error) {
                reject(error);
            }
        });
    }
};

// ================== MÓDULO DE AUTENTICAÇÃO ==================
const AuthModule = {
    async login(email, password, profile) {
        console.log('=== INICIANDO LOGIN ===');
        console.log('Email:', email);
        console.log('Perfil:', profile);
        
        try {
            showLoading('Autenticando...');
            
            // Verificar se o banco está inicializado
            if (!appState.dbInitialized) {
                console.log('Banco não inicializado, aguardando...');
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            
            // Buscar usuário no banco de dados
            console.log('Buscando usuários no banco...');
            const usuarios = await DatabaseModule.getFromStore('usuarios');
            console.log('Usuários encontrados:', usuarios.length);
            
            if (usuarios.length === 0) {
                console.log('Nenhum usuário encontrado, inserindo dados...');
                await DatabaseModule.insertInitialData();
                // Tentar novamente
                const usuariosNovamente = await DatabaseModule.getFromStore('usuarios');
                console.log('Usuários após inserção:', usuariosNovamente.length);
            }
            
            const usuario = usuarios.find(u => u.email === email && u.perfil === profile);
            console.log('Usuário encontrado:', !!usuario);
            
            if (!usuario) {
                throw new Error('Usuário não encontrado ou perfil incorreto');
            }
            
            // Verificar senha
            const passwordHash = CryptoModule.hashPassword(password);
            console.log('Verificando senha...');
            
            if (usuario.senha_hash !== passwordHash) {
                throw new Error('Senha incorreta');
            }
            
            console.log('✓ Autenticação bem-sucedida');
            
            // Gerar token de sessão
            const token = CryptoModule.generateToken(usuario);
            
            // Salvar sessão
            const rememberMe = document.getElementById('remember-me');
            if (rememberMe && rememberMe.checked) {
                localStorage.setItem('authToken', token);
            } else {
                sessionStorage.setItem('authToken', token);
            }
            
            // Definir usuário atual
            appState.currentUser = usuario;
            console.log('Usuário definido no estado:', appState.currentUser.nome);
            
            hideLoading();
            showToast('Login realizado com sucesso!', 'success');
            
            // NAVEGAÇÃO CORRIGIDA - usar setTimeout para garantir que a UI seja atualizada
            console.log('=== INICIANDO NAVEGAÇÃO ===');
            setTimeout(() => {
                console.log('Chamando showContractSelection...');
                showContractSelection();
            }, 100);
            
            return true;
            
        } catch (error) {
            hideLoading();
            console.error('=== ERRO NO LOGIN ===', error);
            showToast('Erro no login: ' + error.message, 'error');
            return false;
        }
    },

    async checkSession() {
        try {
            const token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
            
            if (!token) return false;
            
            const payload = CryptoModule.validateToken(token);
            if (!payload) {
                this.logout();
                return false;
            }
            
            // Buscar dados do usuário
            const usuarios = await DatabaseModule.getFromStore('usuarios');
            const usuario = usuarios.find(u => u.email === payload.user);
            
            if (usuario) {
                appState.currentUser = usuario;
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Erro na verificação de sessão:', error);
            return false;
        }
    },

    logout() {
        localStorage.removeItem('authToken');
        sessionStorage.removeItem('authToken');
        appState.currentUser = null;
        appState.currentContract = null;
        showLoginScreen();
        showToast('Sessão encerrada', 'info');
    }
};

// ================== FUNÇÕES DE INTERFACE ==================
function showLoginScreen() {
    console.log('=== MOSTRANDO TELA DE LOGIN ===');
    
    // Ocultar todas as telas
    const loginScreen = document.getElementById('login-screen');
    const contractScreen = document.getElementById('contract-selection');
    const dashboardScreen = document.getElementById('main-dashboard');
    
    if (loginScreen) loginScreen.classList.remove('hidden');
    if (contractScreen) contractScreen.classList.add('hidden');
    if (dashboardScreen) dashboardScreen.classList.add('hidden');
    
    console.log('✓ Tela de login exibida');
}

function showContractSelection() {
    console.log('=== MOSTRANDO TELA DE CONTRATOS ===');
    
    // Verificar elementos necessários
    const loginScreen = document.getElementById('login-screen');
    const contractScreen = document.getElementById('contract-selection');
    const dashboardScreen = document.getElementById('main-dashboard');
    const userInfoEl = document.getElementById('user-info');
    
    console.log('Elementos encontrados:', {
        loginScreen: !!loginScreen,
        contractScreen: !!contractScreen,
        dashboardScreen: !!dashboardScreen,
        userInfoEl: !!userInfoEl,
        currentUser: !!appState.currentUser
    });
    
    if (!contractScreen || !appState.currentUser) {
        console.error('Erro: elementos necessários não encontrados');
        showToast('Erro ao navegar para seleção de contratos', 'error');
        return;
    }
    
    // Ocultar outras telas
    if (loginScreen) loginScreen.classList.add('hidden');
    if (dashboardScreen) dashboardScreen.classList.add('hidden');
    
    // Mostrar tela de contratos
    contractScreen.classList.remove('hidden');
    
    // Definir informações do usuário
    if (userInfoEl) {
        userInfoEl.textContent = `Logado como: ${appState.currentUser.nome}`;
    }
    
    console.log('✓ Tela de contratos exibida');
    
    // Carregar contratos
    setTimeout(() => {
        console.log('Carregando contratos...');
        loadContracts();
    }, 100);
}

function showMainDashboard() {
    console.log('=== MOSTRANDO DASHBOARD ===');
    
    const loginScreen = document.getElementById('login-screen');
    const contractScreen = document.getElementById('contract-selection');
    const dashboardScreen = document.getElementById('main-dashboard');
    
    if (!dashboardScreen) {
        console.error('Dashboard screen não encontrado');
        return;
    }
    
    // Ocultar outras telas
    if (loginScreen) loginScreen.classList.add('hidden');
    if (contractScreen) contractScreen.classList.add('hidden');
    
    // Mostrar dashboard
    dashboardScreen.classList.remove('hidden');
    
    console.log('✓ Dashboard exibido');
    setupDashboard();
}

async function loadContracts() {
    try {
        console.log('Carregando contratos do banco...');
        const contratos = await DatabaseModule.getFromStore('contratos');
        const grid = document.getElementById('contracts-grid');
        
        if (!grid) {
            console.error('Grid de contratos não encontrado');
            return;
        }
        
        console.log(`${contratos.length} contratos encontrados`);
        
        if (contratos.length === 0) {
            grid.innerHTML = '<p style="text-align: center; color: var(--color-text-secondary);">Nenhum contrato encontrado. Aguarde...</p>';
            
            // Tentar inserir dados novamente
            setTimeout(async () => {
                await DatabaseModule.insertInitialData();
                loadContracts();
            }, 500);
            return;
        }
        
        grid.innerHTML = contratos.map(contrato => `
            <div class="card contract-card" onclick="selectContract(${contrato.id})" style="cursor: pointer;">
                <div class="card__body">
                    <div class="contract-info">
                        <div class="contract-number">${contrato.numero}</div>
                        <div class="contract-object">${contrato.objeto}</div>
                        <div class="contract-company">${contrato.empresa_nome} - ${contrato.empresa_cnpj}</div>
                        <div class="contract-meta">
                            <div class="contract-value">R$ ${contrato.valor_mensal.toLocaleString('pt-BR', {minimumFractionDigits: 2})}/mês</div>
                            <span class="contract-status active">Ativo</span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
        
        console.log('✓ Contratos carregados na interface');
        
    } catch (error) {
        console.error('Erro ao carregar contratos:', error);
        showToast('Erro ao carregar contratos: ' + error.message, 'error');
    }
}

async function selectContract(contractId) {
    try {
        console.log('Selecionando contrato:', contractId);
        const contratos = await DatabaseModule.getFromStore('contratos');
        const contrato = contratos.find(c => c.id === contractId);
        
        if (contrato) {
            appState.currentContract = contrato;
            console.log('Contrato selecionado:', contrato.numero);
            showMainDashboard();
        } else {
            throw new Error('Contrato não encontrado');
        }
    } catch (error) {
        console.error('Erro ao selecionar contrato:', error);
        showToast('Erro ao selecionar contrato: ' + error.message, 'error');
    }
}

function setupDashboard() {
    console.log('Configurando dashboard...');
    
    const dashboardTitle = document.getElementById('dashboard-title');
    const contractInfo = document.getElementById('current-contract-info');
    
    if (dashboardTitle && appState.currentUser) {
        dashboardTitle.textContent = `Dashboard - ${appState.currentUser.perfil.replace('_', ' ').toUpperCase()}`;
    }
    
    if (contractInfo && appState.currentContract) {
        contractInfo.textContent = `${appState.currentContract.numero} - ${appState.currentContract.objeto}`;
    }
    
    // Configurar tabs baseado no perfil
    setupTabs();
    setupFileUpload();
    loadDocuments();
    loadValidations();
}

function setupTabs() {
    const tabsNav = document.getElementById('dashboard-tabs');
    const userProfile = appState.currentUser?.perfil;
    
    if (!tabsNav || !userProfile) {
        console.error('Erro no setup das tabs:', { tabsNav: !!tabsNav, userProfile });
        return;
    }
    
    let tabs = [];
    
    if (userProfile === 'fiscal_administrativo' || userProfile === 'admin') {
        tabs = [
            { id: 'upload-tab', name: 'Upload de Documentos', icon: 'fas fa-upload' },
            { id: 'validations-tab', name: 'Validações', icon: 'fas fa-check-circle' },
            { id: 'reports-tab', name: 'Relatórios', icon: 'fas fa-file-pdf' }
        ];
    } else if (userProfile === 'fiscal_tecnico') {
        tabs = [
            { id: 'upload-tab', name: 'Upload Técnico', icon: 'fas fa-upload' },
            { id: 'validations-tab', name: 'Avaliações', icon: 'fas fa-tasks' },
            { id: 'reports-tab', name: 'Relatórios', icon: 'fas fa-file-pdf' }
        ];
    }
    
    if (userProfile === 'admin') {
        tabs.push({ id: 'config-tab', name: 'Configurações', icon: 'fas fa-cog' });
    }
    
    tabsNav.innerHTML = tabs.map(tab => `
        <li>
            <button class="tab-btn ${tab.id === 'upload-tab' ? 'active' : ''}" onclick="switchTab('${tab.id}')">
                <i class="${tab.icon}"></i> ${tab.name}
            </button>
        </li>
    `).join('');
    
    setupDocumentTypes();
}

function setupDocumentTypes() {
    const documentTypeSelect = document.getElementById('document-type');
    const userProfile = appState.currentUser?.perfil;
    
    if (!documentTypeSelect || !userProfile) return;
    
    let types = [];
    
    if (userProfile === 'fiscal_administrativo' || userProfile === 'admin') {
        types = [
            { value: 'FOLHA_PAGAMENTO', label: 'Folha de Pagamento' },
            { value: 'CND_FEDERAL', label: 'CND Federal' },
            { value: 'CRF_FGTS', label: 'CRF FGTS' },
            { value: 'CNDT_TRABALHISTA', label: 'CNDT Trabalhista' },
            { value: 'COMPROVANTE_PAGAMENTO', label: 'Comprovante de Pagamento' },
            { value: 'GUIA_INSS', label: 'Guia INSS' },
            { value: 'GUIA_FGTS', label: 'Guia FGTS' }
        ];
    } else if (userProfile === 'fiscal_tecnico') {
        types = [
            { value: 'RELATORIO_TECNICO', label: 'Relatório Técnico' },
            { value: 'FOTO_EVIDENCIA', label: 'Foto de Evidência' },
            { value: 'LAUDO_TECNICO', label: 'Laudo Técnico' }
        ];
    }
    
    documentTypeSelect.innerHTML = `
        <option value="">Selecione o tipo</option>
        ${types.map(type => `<option value="${type.value}">${type.label}</option>`).join('')}
    `;
}

function setupFileUpload() {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    
    if (!uploadArea || !fileInput) return;
    
    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        const files = Array.from(e.dataTransfer.files);
        handleFileUpload(files);
    });
    
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        handleFileUpload(files);
    });
}

async function handleFileUpload(files) {
    const documentTypeElem = document.getElementById('document-type');
    const documentType = documentTypeElem ? documentTypeElem.value : null;

    if (!documentType) {
        showToast('Selecione o tipo de documento antes de fazer upload', 'warning');
        return;
    }

    showLoading('Processando arquivos...');

    for (const file of files) {
        try {
            console.log('Processando arquivo:', file.name);
            // Run OCR (works for images; PDF supported only if browser handles it)
            let extractedText = '';
            try {
                extractedText = await runOCR(file);
            } catch (err) {
                console.warn('OCR falhou para', file.name, err);
                extractedText = ''; // continue, store file metadata
            }

            const documento = {
                contrato_id: appState.currentContract ? appState.currentContract.id : null,
                nome: file.name,
                tipo: documentType,
                texto_extraido: extractedText,
                tamanho: file.size,
                tipo_mime: file.type,
                data_upload: new Date().toISOString()
            };

            // Save document (use addToStore for new)
            try {
                const id = await DatabaseModule.addToStore('documentos', documento);
                documento.id = id;
            } catch (e) {
                // fallback to saveToStore if add fails (e.g., key exists)
                await DatabaseModule.saveToStore('documentos', documento);
            }

            // Run simple validations and persist issues
            const issues = runValidationsOnText(extractedText, documento);
            for (const inc of issues) {
                await DatabaseModule.addToStore('inconsistencias', inc);
            }

            showToast(`Arquivo ${file.name} processado. ${issues.length} inconsistência(s) detectada(s).`, 'success');
        } catch (error) {
            console.error('Erro ao processar arquivo', file.name, error);
            showToast(`Erro ao processar ${file.name}`, 'error');
        }
    }

    hideLoading();
    // refresh UI (if functions exist)
    if (typeof loadDocuments === 'function') loadDocuments();
    if (typeof loadValidations === 'function') loadValidations();
}

async function loadDocuments() {
    try {
        const documentos = await DatabaseModule.getFromStore('documentos');
        appState.documents = documentos.filter(d => d.contrato_id === appState.currentContract.id);
    } catch (error) {
        console.error('Erro ao carregar documentos:', error);
    }
}

async function loadValidations() {
    try {
        updateValidationStats();
        renderInconsistencies();
    } catch (error) {
        console.error('Erro ao carregar validações:', error);
    }
}

function updateValidationStats() {
    const validDocsEl = document.getElementById('valid-docs');
    const invalidDocsEl = document.getElementById('invalid-docs');
    const pendingDocsEl = document.getElementById('pending-docs');
    
    if (validDocsEl) validDocsEl.textContent = '0';
    if (invalidDocsEl) invalidDocsEl.textContent = '0';
    if (pendingDocsEl) pendingDocsEl.textContent = '0';
}

function renderInconsistencies() {
    const container = document.getElementById('inconsistencies-list');
    
    if (!container) return;
    
    container.innerHTML = '<p style="text-align: center; color: var(--color-text-secondary);">Nenhuma inconsistência encontrada.</p>';
}

function switchTab(tabId) {
    console.log('Mudando para tab:', tabId);
    
    // Remover active de todas as tabs
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Ativar tab selecionada
    const tabBtn = document.querySelector(`button[onclick="switchTab('${tabId}')"]`);
    const tabContent = document.getElementById(tabId);
    
    if (tabBtn) {
        tabBtn.classList.add('active');
        console.log('✓ Tab button ativado');
    }
    
    if (tabContent) {
        tabContent.classList.add('active');
        console.log('✓ Tab content ativado');
    }
}

async function generateReport() {
    showToast('Gerando relatório simulado...', 'info');
    console.log('Relatório simulado gerado');
}

// ================== FUNÇÕES AUXILIARES ==================
function togglePassword() {
    const passwordInput = document.getElementById('password');
    const toggleBtn = document.querySelector('.password-toggle i');
    
    if (passwordInput && toggleBtn) {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.classList.replace('fa-eye', 'fa-eye-slash');
        } else {
            passwordInput.type = 'password';
            toggleBtn.classList.replace('fa-eye-slash', 'fa-eye');
        }
    }
}

function showLoading(message = 'Carregando...') {
    const loadingText = document.getElementById('loading-text');
    const loadingOverlay = document.getElementById('loading-overlay');
    
    if (loadingText) loadingText.textContent = message;
    if (loadingOverlay) loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
    const loadingOverlay = document.getElementById('loading-overlay');
    if (loadingOverlay) loadingOverlay.classList.add('hidden');
}

function showToast(message, type = 'info') {
    console.log(`Toast [${type}]: ${message}`);
    
    const container = document.getElementById('toast-container');
    
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        if (toast && toast.parentNode) {
            toast.remove();
        }
    }, 5000);
}


// ============== OCR & VALIDATION HELPERS ==============
async function initOCRWorker() {
    if (appState.ocrWorker) return appState.ocrWorker;
    if (typeof Tesseract === 'undefined' || !Tesseract.createWorker) {
        console.warn('Tesseract.js não disponível no ambiente. OCR será ignorado.');
        return null;
    }
    const worker = Tesseract.createWorker({
        logger: m => {
            // progresso opcional
            // console.log('[TESSERACT]', m);
        }
    });
    await worker.load();
    await worker.loadLanguage('por');
    await worker.initialize('por');
    appState.ocrWorker = worker;
    return worker;
}

async function runOCR(file) {
    try {
        const worker = await initOCRWorker();
        if (!worker) return '';
        // create object URL for file
        const url = URL.createObjectURL(file);
        const { data: { text } } = await worker.recognize(url);
        URL.revokeObjectURL(url);
        return text || '';
    } catch (err) {
        console.error('runOCR error:', err);
        return '';
    }
}

// Simple rule engine for validations - extend as needed
function runValidationsOnText(text, documento) {
    const issues = [];
    if (!text || text.trim().length === 0) {
        issues.push({
            contrato_id: documento.contrato_id,
            documento_id: documento.id || null,
            tipo: 'TEXT_EMPTY',
            descricao: 'Texto extraído está vazio.',
            nivel: 'warning',
            criado_em: new Date().toISOString()
        });
        return issues;
    }
    // CNPJ regex (formatted)
    const cnpjRegex = /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g;
    const cnpjFound = text.match(cnpjRegex);
    if (!cnpjFound) {
        issues.push({
            contrato_id: documento.contrato_id,
            documento_id: documento.id || null,
            tipo: 'CNPJ_MISSING',
            descricao: 'CNPJ não encontrado no documento.',
            nivel: 'warning',
            criado_em: new Date().toISOString()
        });
    }
    // Valor em Reais
    const valorRegex = /R\$\s?[\d\.\,]+/g;
    const valores = text.match(valorRegex);
    if (!valores || valores.length === 0) {
        issues.push({
            contrato_id: documento.contrato_id,
            documento_id: documento.id || null,
            tipo: 'VALOR_MISSING',
            descricao: 'Valor em R$ não encontrado no documento.',
            nivel: 'info',
            criado_em: new Date().toISOString()
        });
    }
    return issues;
}

// ============== END OCR & VALIDATION HELPERS ==============

// ============== CONTRACT & TERM MANAGEMENT ==============

/**
 * addContract(contractObj)
 * contractObj = {
 *   numero, titulo, contratado, valor, data_inicio, data_termino
 * }
 */
async function addContract(contractObj) {
    // convert numeric value
    contractObj.valor = Number(contractObj.valor) || 0;
    contractObj.created_at = new Date().toISOString();
    try {
        const id = await DatabaseModule.addToStore('contratos', contractObj);
        showToast('Contrato adicionado', 'success');
        if (typeof loadContracts === 'function') loadContracts();
        return id;
    } catch (err) {
        console.error('addContract error', err);
        showToast('Falha ao adicionar contrato', 'error');
        throw err;
    }
}

async function addAditivo(aditivoObj) {
    aditivoObj.valor = Number(aditivoObj.valor) || 0;
    aditivoObj.created_at = new Date().toISOString();
    try {
        const id = await DatabaseModule.addToStore('aditivos', aditivoObj);
        showToast('Termo aditivo adicionado', 'success');
        if (typeof loadContracts === 'function') loadContracts();
        return id;
    } catch (err) {
        console.error('addAditivo error', err);
        showToast('Falha ao adicionar aditivo', 'error');
        throw err;
    }
}

async function addProrrogacao(prorroObj) {
    prorroObj.created_at = new Date().toISOString();
    try {
        const id = await DatabaseModule.addToStore('prorrogacoes', prorroObj);
        showToast('Prorrogação adicionada', 'success');
        if (typeof loadContracts === 'function') loadContracts();
        return id;
    } catch (err) {
        console.error('addProrrogacao error', err);
        showToast('Falha ao adicionar prorrogação', 'error');
        throw err;
    }
}

async function loadContracts() {
    try {
        const contratos = await DatabaseModule.getFromStore('contratos');
        const aditivos = await DatabaseModule.getFromStore('aditivos');
        const prorrogacoes = await DatabaseModule.getFromStore('prorrogacoes');
        renderContracts(contratos || [], aditivos || [], prorrogacoes || []);
    } catch (err) {
        console.error('loadContracts error', err);
    }
}

function renderContracts(contratos, aditivos, prorrogacoes) {
    const container = document.getElementById('contracts-container');
    if (!container) return;
    container.innerHTML = '';
    contratos.forEach(c => {
        const cAditivos = (aditivos || []).filter(a => a.contrato_numero === c.numero);
        const cPror = (prorrogacoes || []).filter(p => p.contrato_numero === c.numero);
        // compute adjusted value
        const somaAditivos = cAditivos.reduce((s, a) => s + (Number(a.valor)||0), 0);
        const valorAtual = (Number(c.valor)||0) + somaAditivos;
        const currentEnd = cPror.length ? cPror[cPror.length-1].nova_data_termino : c.data_termino;
        const item = document.createElement('div');
        item.className = 'contract-item';
        item.innerHTML = `<div class="meta"><strong>${c.numero} - ${c.titulo}</strong><div>Contratado: ${c.contratado}</div><div>Valor original: R$ ${Number(c.valor).toFixed(2)} | Valor atual: R$ ${Number(valorAtual).toFixed(2)}</div><div>Vigência: ${c.data_inicio} → ${currentEnd}</div></div>
                          <div class="actions"><button type="button" onclick="viewContractDetails('${c.numero}')">Ver</button></div>`;
        container.appendChild(item);
    });
}

function viewContractDetails(numero) {
    // simple modal display using alert for now, can be improved
    (async () => {
        const contratos = await DatabaseModule.getFromStore('contratos');
        const c = (contratos || []).find(x => x.numero === numero);
        if (!c) { showToast('Contrato não encontrado', 'warning'); return; }
        const aditivos = await DatabaseModule.getFromStore('aditivos');
        const prorrogacoes = await DatabaseModule.getFromStore('prorrogacoes');
        const cAditivos = (aditivos || []).filter(a => a.contrato_numero === c.numero);
        const cPror = (prorrogacoes || []).filter(p => p.contrato_numero === c.numero);
        let msg = `Contrato ${c.numero} - ${c.titulo}\nContratado: ${c.contratado}\nValor original: R$ ${Number(c.valor).toFixed(2)}\nVigência: ${c.data_inicio} → ${c.data_termino}\n\nAditivos:\n`;
        if (cAditivos.length===0) msg += ' - Nenhum aditivo\n'; else cAditivos.forEach(a => msg += ` - ${a.aditivo_number || a.numero}: +R$ ${Number(a.valor).toFixed(2)} em ${a.created_at}\n`);
        msg += '\nProrrogações:\n';
        if (cPror.length===0) msg += ' - Nenhuma prorrogação\n'; else cPror.forEach(p => msg += ` - Nova data término: ${p.nova_data_termino} (motivo: ${p.motivo || p.reason})\n`);
        alert(msg);
    })();
}

// Validation: check expirations and value mismatches
async function validateContracts() {
    const contratos = await DatabaseModule.getFromStore('contratos') || [];
    const aditivos = await DatabaseModule.getFromStore('aditivos') || [];
    const prorrogacoes = await DatabaseModule.getFromStore('prorrogacoes') || [];
    const issues = [];
    contratos.forEach(c => {
        const cAditivos = aditivos.filter(a => a.contrato_numero === c.numero);
        const somaAditivos = cAditivos.reduce((s, a) => s + (Number(a.valor)||0), 0);
        const valorAtual = (Number(c.valor)||0) + somaAditivos;
        // if any documento refers a different value, flag (simple heuristic)
        // search documentos for lines containing R$ and the contract number
        // naive: count documents mentioning contract number and values
        // This is just an example; expand with robust parsing if needed.
        const docs = (await DatabaseModule.getFromStore('documentos')) || [];
        const relatedDocs = docs.filter(d => (d.texto_extraido || '').includes(c.numero) || d.contrato_id === c.id);
        relatedDocs.forEach(d => {
            const foundVals = (d.texto_extraido || '').match(/R\$\s?[\d\.\,]+/g) || [];
            foundVals.forEach(fv => {
                // clean number
                const num = Number(fv.replace(/[R\$\.\s]/g,'').replace(',', '.'));
                if (!isNaN(num) && Math.abs(num - valorAtual) / Math.max(1, valorAtual) > 0.05) {
                    issues.push({
                        contrato_numero: c.numero,
                        documento_id: d.id || null,
                        tipo: 'VALOR_DIVERGENTE',
                        descricao: `Valor declarado no documento (${fv}) diverge do valor atual do contrato (R$ ${valorAtual.toFixed(2)}).`,
                        nivel: 'warning',
                        criado_em: new Date().toISOString()
                    });
                }
            });
        });
        // check expiration: if no active prorrogação and end date passed
        const lastPror = prorrogacoes.filter(p => p.contrato_numero === c.numero).sort((a,b)=> (a.created_at||'') > (b.created_at||'') ? 1:-1).pop();
        const effectiveEnd = lastPror ? lastPror.nova_data_termino : c.data_termino;
        if (effectiveEnd && new Date(effectiveEnd) < new Date()) {
            issues.push({
                contrato_numero: c.numero,
                tipo: 'CONTRATO_VENCIDO',
                descricao: `Contrato com término em ${effectiveEnd} já expirou.`,
                nivel: 'error',
                criado_em: new Date().toISOString()
            });
        }
    });
    // persist issues to inconsistencias store
    for (const inc of issues) {
        await DatabaseModule.addToStore('inconsistencias', inc);
    }
    showToast(`${issues.length} inconsistência(s) de contrato detectada(s)`, issues.length? 'warning' : 'success');
    return issues;
}

// ============== END CONTRACT & TERM MANAGEMENT ==============



function logout() {
    AuthModule.logout();
}

function openAddContractModal() {
    const modal = document.getElementById('add-contract-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('hidden');
}

// ================== INICIALIZAÇÃO DA APLICAÇÃO ==================
document.addEventListener('DOMContentLoaded', async function() {
    console.log('=== INICIALIZANDO SISTEMA ===');
    
    try {
        // Inicializar banco de dados
        console.log('Inicializando banco...');
        await DatabaseModule.init();
        
        // Aguardar banco estar pronto
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Verificar sessão existente
        const hasSession = await AuthModule.checkSession();
        
        if (hasSession && appState.currentUser) {
            console.log('Sessão existente encontrada');
            showContractSelection();
        } else {
            console.log('Nenhuma sessão encontrada');
            showLoginScreen();
        }
        
        // Configurar form de login
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            console.log('Configurando form de login...');
            
            loginForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                console.log('Form de login submetido');
                
                const emailEl = document.getElementById('email');
                const passwordEl = document.getElementById('password');
                const profileEl = document.getElementById('profile');
                
                const email = emailEl ? emailEl.value.trim() : '';
                const password = passwordEl ? passwordEl.value : '';
                const profile = profileEl ? profileEl.value : '';
                
                console.log('Dados do form:', { email, hasPassword: !!password, profile });
                
                if (!email || !password || !profile) {
                    showToast('Preencha todos os campos', 'warning');
                    return;
                }
                
                // Chamar login
                const success = await AuthModule.login(email, password, profile);
                console.log('Resultado do login:', success);
            });
        }
        
        console.log('✓ Sistema inicializado com sucesso');
        
    } catch (error) {
        console.error('=== ERRO NA INICIALIZAÇÃO ===', error);
        showToast('Erro na inicialização: ' + error.message, 'error');
    }
});

// ================== EXPOR FUNÇÕES GLOBALMENTE ==================


// ============== UI HOOKS FOR CONTRACT FORMS ==============
function setupContractFormHooks() {
    const btnAddContract = document.getElementById('btn-add-contract');
    if (btnAddContract) {
        btnAddContract.addEventListener('click', async () => {
            const numero = document.getElementById('contract-number').value.trim();
            const titulo = document.getElementById('contract-title').value.trim();
            const contratado = document.getElementById('contract-contractor').value.trim();
            const valor = document.getElementById('contract-value').value.trim();
            const data_inicio = document.getElementById('contract-start').value;
            const data_termino = document.getElementById('contract-end').value;
            if (!numero || !titulo) { showToast('Preencha número e título', 'warning'); return; }
            await addContract({ numero, titulo, contratado, valor, data_inicio, data_termino });
            // clear form
            document.getElementById('add-contract-form').reset();
        });
    }

    const btnAddAditivo = document.getElementById('btn-add-aditivo');
    if (btnAddAditivo) {
        btnAddAditivo.addEventListener('click', async () => {
            const contrato_numero = document.getElementById('aditivo-contract-number').value.trim();
            const aditivo_number = document.getElementById('aditivo-number').value.trim();
            const valor = document.getElementById('aditivo-value').value.trim();
            const data = document.getElementById('aditivo-date').value;
            if (!contrato_numero || !aditivo_number) { showToast('Preencha contrato e número do aditivo', 'warning'); return; }
            await addAditivo({ contrato_numero, aditivo_number, valor, data, criado_em: new Date().toISOString() });
            document.getElementById('add-aditivo-form').reset();
        });
    }

    const btnAddProrro = document.getElementById('btn-add-prorro');
    if (btnAddProrro) {
        btnAddProrro.addEventListener('click', async () => {
            const contrato_numero = document.getElementById('prorro-contract-number').value.trim();
            const nova_data_termino = document.getElementById('prorro-new-end').value;
            const motivo = document.getElementById('prorro-reason').value.trim();
            if (!contrato_numero || !nova_data_termino) { showToast('Preencha contrato e nova data', 'warning'); return; }
            await addProrrogacao({ contrato_numero, nova_data_termino, motivo, criado_em: new Date().toISOString() });
            document.getElementById('add-prorrogacao-form').reset();
        });
    }
}

// Call setup after init completes (hook into existing init flow)
document.addEventListener('DOMContentLoaded', () => {
    try {
        setupContractFormHooks();
        // load existing contracts to render
        if (typeof loadContracts === 'function') loadContracts();
    } catch (e) {
        console.warn('setupContractFormHooks error', e);
    }
});
window.selectContract = selectContract;
window.switchTab = switchTab;
window.generateReport = generateReport;
window.togglePassword = togglePassword;
window.logout = logout;
window.openAddContractModal = openAddContractModal;
window.closeModal = closeModal;