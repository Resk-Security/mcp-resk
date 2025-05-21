"""
Exemple de serveur MCP sécurisé utilisant resk-mcp.
Ce fichier montre comment configurer et démarrer un serveur avec:
- Validation de schéma 
- Sécurité RESK-LLM
- Traitement sécurisé des outils

Pour exécuter: python example_server.py
"""

import asyncio
import logging
import uvicorn
import os
from typing import Dict, Any
from dotenv import load_dotenv

from resk_mcp.server import SecureMCPServer
from resk_mcp.schema_validation import ToolSchemaValidator
from resk_mcp.security import MCPSecurityManager
from resk_mcp.auth import create_jwt_token
from resk_mcp.config import settings

# Charger les variables d'environnement depuis .env au tout début
load_dotenv()

# Configuration du logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("example-server")

# La variable JWT_SECRET est chargée et validée par resk_mcp.config.settings lors de son initialisation.
# Si JWT_SECRET n'est pas trouvé dans .env ou config.yaml, resk_mcp.config lèvera une ValueError.
# Il n'est donc pas nécessaire de le réaffecter ou de le revérifier ici.


tool_validator = ToolSchemaValidator()

# Schémas pour nos outils
CALCULATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "a": {"type": "number"},
        "b": {"type": "number"}
    },
    "required": ["a", "b"]
}

GREETING_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "language": {"type": "string", "enum": ["en", "fr", "es"]}
    },
    "required": ["name"]
}

# Créer un gestionnaire de sécurité
security_manager = MCPSecurityManager(
    enable_heuristic_filter=True,
    enable_content_moderation=False,  # Désactiver pour l'exemple
    enable_pii_detection=True,
    enable_url_detection=True,
    enable_ip_protection=True
)

# Créer le serveur sécurisé
server = SecureMCPServer(
    name="exemple-serveur-securise",
    security_manager=security_manager,
    verbose=True
)

# Enregistrer les schémas pour les outils explicitement
tool_validator.register_schema("calculator/add", CALCULATOR_SCHEMA)
tool_validator.register_schema("greeting/hello", GREETING_SCHEMA)

@server.tool(name="calculator/add")
async def add(a: float, b: float) -> float:
    """Additionne deux nombres."""
    return a + b

@server.tool(name="greeting/hello")
async def hello(name: str, language: str = "fr") -> str:
    """Salue une personne dans la langue spécifiée."""
    if not name:
        return "Error: name is required"
    
    greetings = {
        "en": f"Hello, {name}!",
        "fr": f"Bonjour, {name}!",
        "es": f"Hola, {name}!"
    }
    
    return greetings.get(language, greetings["fr"])

if __name__ == "__main__":
    # Log pour voir les outils enregistrés directement dans le serveur
    if hasattr(server, "tool_registry") and server.tool_registry: # Safely check if attribute exists
        logger.info(f"Outils enregistrés dans SecureMCPServer (tool_registry): {list(server.tool_registry.keys())}")
    elif hasattr(server, "tools") and server.tools: # Alternative common name
        logger.info(f"Outils enregistrés dans SecureMCPServer (tools): {list(server.tools.keys())}")
    else:
        logger.info("Impossible d'accéder directement à la liste des outils enregistrés dans SecureMCPServer pour le débogage.")

    # Générer un token JWT valide pour test
    test_user_id = "test_user"
    # create_jwt_token utilisera settings.jwt_secret qui est maintenant chargé depuis .env
    token = create_jwt_token(user_id=test_user_id)
    logger.info(f"Token de test généré (utilisant JWT_SECRET du .env): {token}")
    
    # Obtenir l'application FastAPI directement
    app = server.secure_app
    
    # Démarrer le serveur avec uvicorn directement
    PORT = 8001
    HOST = "0.0.0.0"
    logger.info(f"Démarrage du serveur sur http://{HOST}:{PORT}")
    logger.info(f"URL de l'API MCP: http://localhost:{PORT}/mcp_secure")
    uvicorn.run(app, host=HOST, port=PORT) 