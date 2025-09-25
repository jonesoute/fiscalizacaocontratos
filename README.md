# Sistema de Fiscalização de Contratos Públicos

## 🚀 Sobre o Projeto

Sistema web para fiscalização de contratos de terceirização com auxílio de **Inteligência Artificial**, desenvolvido especificamente para servidores públicos federais.

### ✨ Funcionalidades Principais

- 🔐 **Autenticação Segura** com criptografia AES-256
- 📄 **Upload e OCR Automático** de documentos (PDF, XLSX, imagens)
- ⚖️ **Validação Inteligente** de obrigações trabalhistas
- 🎯 **Diferenciação por Contrato** com regras específicas
- 📊 **Relatórios Detalhados** com rastreabilidade completa
- 💾 **Armazenamento Offline** com IndexedDB
- 🔄 **Sincronização Automática** quando online

### 🛡️ Segurança Implementada

- ✅ Criptografia **AES-256** para dados sensíveis
- ✅ Hash **SHA-256** para senhas
- ✅ **Sanitização** de inputs
- ✅ **Tokens JWT** para sessões
- ✅ **Validação** de tipos de arquivo

## 🎯 Perfis de Usuário

### 👨‍💼 Fiscal Administrativo
- Validação de documentos trabalhistas
- Conferência de certidões (CND, CRF, CNDT)
- Análise de folhas de pagamento
- Verificação de FGTS e INSS

### 🔧 Fiscal Técnico  
- Avaliação de qualidade dos serviços
- Registro de ocorrências técnicas
- Upload de evidências fotográficas
- Relatórios de performance

### ⚙️ Administrador
- Gestão de contratos e regras
- Configuração de validações
- Relatórios gerenciais
- Controle de usuários

## 🚀 Como Usar

### 1. Credenciais de Teste

**Administrador:**
- Email: `admin@orgao.gov.br`
- Senha: `admin123`

**Fiscal Administrativo:**
- Email: `fiscal.admin@orgao.gov.br`
- Senha: `fiscal123`

**Fiscal Técnico:**
- Email: `fiscal.tecnico@orgao.gov.br`
- Senha: `fiscal123`

### 2. Fluxo de Uso

1. **Login** → Escolha seu perfil de usuário
2. **Seleção de Contrato** → Escolha qual contrato fiscalizar
3. **Upload de Documentos** → Arraste arquivos ou use a câmera
4. **Análise Automática** → IA processa e valida documentos
5. **Revisão** → Confira inconsistências encontradas
6. **Relatório** → Gere relatório final com rastreabilidade

## 🏗️ Arquitetura Técnica

### Frontend
- **HTML5** com estrutura semântica
- **CSS3** com design responsivo
- **JavaScript ES6+** modular
- **Bootstrap 5** para interface

### Bibliotecas Utilizadas
- **Tesseract.js** - OCR (Reconhecimento Ótico de Caracteres)
- **CryptoJS** - Criptografia AES-256 e SHA-256
- **Chart.js** - Gráficos e indicadores
- **jsPDF** - Geração de relatórios PDF
- **FontAwesome** - Ícones

### Banco de Dados
- **IndexedDB** para armazenamento local
- **Estrutura criptografada** para dados sensíveis
- **Backup automático** para JSON

## 📁 Estrutura do Projeto

```
fiscalizacao-contratos/
├── index.html          # Tela de login
├── style.css           # Estilos principais
├── app.js              # Aplicação principal
├── README.md           # Este arquivo
└── .github/
    └── workflows/
        └── deploy.yml  # Deploy automático
```

## 🔧 Instalação no GitHub Pages

### 1. Fork este repositório
```bash
# Clone o repositório
git clone https://github.com/seu-usuario/fiscalizacao-contratos.git
cd fiscalizacao-contratos
```

### 2. Ative o GitHub Pages
1. Vá em **Settings** do repositório
2. Clique em **Pages**
3. Em **Source**, selecione **Deploy from a branch**
4. Escolha **main** branch e **/ (root)**
5. Clique em **Save**

### 3. Acesse sua aplicação
Sua aplicação estará disponível em:  
`https://seu-usuario.github.io/fiscalizacao-contratos/`

## 🎯 Funcionalidades Implementadas

### ✅ MVP Atual (Versão 1.0)
- [x] Sistema de login com múltiplos perfis
- [x] Seleção e configuração de contratos
- [x] Upload de documentos com drag-and-drop
- [x] OCR automático com Tesseract.js
- [x] Validações básicas de documentos trabalhistas
- [x] Interface para Fiscal Administrativo e Técnico
- [x] Relatórios com rastreabilidade
- [x] Armazenamento offline seguro
- [x] Criptografia de dados sensíveis

### 🔄 Próximas Versões (Roadmap)

#### Versão 2.0 (6 meses)
- [ ] Integração com APIs governamentais
- [ ] Machine Learning para classificação automática
- [ ] Dashboard analítico avançado
- [ ] Sistema de notificações
- [ ] Backup para cloud

#### Versão 3.0 (12 meses)
- [ ] Aplicativo mobile (React Native)
- [ ] Workflows de aprovação hierárquica
- [ ] Integração com sistemas legados
- [ ] IA avançada para detecção de fraudes
- [ ] Multi-órgão

## 🛠️ Expansibilidade

O código foi estruturado com **ganchos para expansão**:

### Novos Perfis de Usuário
```javascript
// EXPANSÃO: Adicionar novos perfis em app.js
const USER_PROFILES = {
    admin: 'Administrador',
    fiscal_administrativo: 'Fiscal Administrativo', 
    fiscal_tecnico: 'Fiscal Técnico',
    // EXPANSÃO: Adicionar aqui novos perfis
    gestor_contrato: 'Gestor de Contrato',
    ordenador_despesas: 'Ordenador de Despesas'
};
```

### Novos Tipos de Validação
```javascript
// EXPANSÃO: Adicionar validações em ValidationModule
validateCustomRule(document, rule) {
    // EXPANSÃO: Implementar novas regras de validação
    switch(rule.type) {
        case 'NOVA_REGRA':
            return this.validateNovaRegra(document, rule);
        // ...
    }
}
```

### Integração com Backend
```javascript
// EXPANSÃO: APIs prontas para integração
const API_ENDPOINTS = {
    // EXPANSÃO: Substituir por URLs reais do backend
    login: '/api/auth/login',
    contracts: '/api/contracts',
    documents: '/api/documents',
    validations: '/api/validations'
};
```

## 📊 Validações Implementadas

### Documentos Trabalhistas
- **FGTS**: Verifica 8% do salário bruto
- **INSS**: Verifica percentuais corretos
- **Salário Mínimo**: Valida valores mínimos
- **Prazos**: Confirma datas de pagamento

### Certidões
- **CND Federal**: Valida formato e vencimento
- **CRF (FGTS)**: Verifica regularidade
- **CNDT**: Confirma ausência de débitos trabalhistas

## 🤝 Contribuição

1. Faça um **fork** do projeto
2. Crie uma **branch** para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. **Push** para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um **Pull Request**

## 📝 Licença

Este projeto está sob a licença **MIT**. Veja o arquivo `LICENSE` para mais detalhes.

## 📞 Suporte

Para dúvidas ou sugestões:
- Abra uma **issue** no GitHub
