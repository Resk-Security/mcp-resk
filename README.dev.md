# Guide de développement RESK-MCP

Ce guide explique comment tester et utiliser la bibliothèque RESK-MCP en tant que développeur.

## Installation

Pour installer la bibliothèque en mode développement:

```bash
pip install -e .
```

Cette commande installe le package en mode éditable, ce qui signifie que les modifications apportées au code source seront immédiatement disponibles sans avoir à réinstaller.

## Tests unitaires

Pour exécuter tous les tests unitaires:

```bash
python -m pytest
```

Pour exécuter des tests spécifiques:

```bash
python -m pytest tests/test_schema_validation.py
python -m pytest tests/test_security.py
```

## Exemples fournis

### 1. Script de test simple

Le fichier `test_dev.py` présente les fonctionnalités de base de validation de schéma et de sécurité:

```bash
python test_dev.py
```

Ce script montre comment utiliser:
- `ToolSchemaValidator` pour valider les paramètres des outils
- `MCPSecurityManager` pour détecter et prévenir les menaces de sécurité

### 2. Serveur MCP sécurisé

Le fichier `example_server.py` montre comment créer un serveur MCP sécurisé avec:
- Validation de schéma JSON
- Sécurité intégrée
- Définition d'outils

Pour démarrer le serveur:

```bash
python example_server.py
```

Le serveur démarre sur le port 8000 et propose deux outils:
- `calculator/add`: Additionne deux nombres
- `greeting/hello`: Génère un message de salutation dans différentes langues

### 3. Client de test

Le fichier `test_client.py` permet d'interagir avec le serveur:

```bash
python test_client.py
```

Vous pouvez choisir parmi différents tests:
- Test de l'outil calculator/add
- Test de l'outil greeting/hello
- Test des fonctionnalités de sécurité

Pour exécuter tous les tests automatiquement:

```bash
python test_client.py --all
```

## Utilisation dans vos propres projets

### Intégration du schéma JSON

```python
from resk_mcp.schema_validation import ToolSchemaValidator, tool_validator

# Définir un schéma
SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "temperature": {"type": "number", "minimum": 0, "maximum": 1}
    },
    "required": ["query"]
}

# Enregistrer le schéma
tool_validator.register_schema("my_tool/search", SCHEMA)

# Valider des paramètres
try:
    validated_params = tool_validator.validate_parameters("my_tool/search", user_params)
    # Utiliser validated_params
except SchemaValidationError as e:
    # Gérer l'erreur
```

### Intégration de la sécurité

```python
from resk_mcp.security import MCPSecurityManager

# Créer un gestionnaire de sécurité
security = MCPSecurityManager(
    enable_heuristic_filter=True,
    enable_pii_detection=True,
    enable_url_detection=True
)

# Sécuriser une requête
secured_params, security_info = security.secure_mcp_request(
    "my_tool/search", 
    user_params,
    user_id="user123"
)

# Vérifier les résultats de sécurité
if security_info["is_blocked"]:
    # Requête bloquée pour raison de sécurité
    reason = security_info["block_reason"]
elif security_info["is_suspicious"]:
    # Requête suspecte mais traitée
    risk_score = security_info["risk_score"]
    checks = security_info["security_checks"]
```

### Intégration complète avec un serveur MCP

```python
from resk_mcp.server import SecureMCPServer
from resk_mcp.schema_validation import tool_validator
from resk_mcp.security import MCPSecurityManager

# Configuration
security = MCPSecurityManager(...)
server = SecureMCPServer(name="my-server", security_manager=security)

# Enregistrer des schémas
tool_validator.register_schema("my_tool/search", SEARCH_SCHEMA)

# Définir des outils
@server.tool(name="my_tool/search")
async def search(query: str, temperature: float = 0.7):
    # Implémentation de l'outil
    return {"results": [...]}

# Démarrer le serveur
await server.start()
```

## Notes sur resk-llm

Pour utiliser toutes les fonctionnalités de sécurité avancées, vous devrez installer la bibliothèque `resk-llm`:

```bash
pip install resk-llm>=0.5.0
```

Sans cette bibliothèque, certaines fonctionnalités de sécurité seront désactivées ou simulées. 