#!/bin/bash

# Script de configuration pour l'environnement CI/CD

echo "🔧 Configuration de l'environnement pour la pipeline CI/CD..."

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé. Installation impossible."
    exit 1
fi

# Créer le fichier .secrets.baseline s'il n'existe pas
if [ ! -f .secrets.baseline ]; then
    echo "📝 Création du fichier .secrets.baseline pour detect-secrets"
    echo '{"version": "1.0.0", "plugins_used": [{"name": "ArtifactoryDetector"}, {"name": "AWSKeyDetector"}, {"name": "BasicAuthDetector"}, {"name": "CloudantDetector"}, {"name": "GitHubTokenDetector"}, {"name": "PrivateKeyDetector"}, {"name": "SlackDetector"}, {"name": "StripeDetector"}], "filters_used": [{"path": "detect_secrets.filters.allowlist.is_line_allowlisted"}, {"path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies", "min_level": 2}, {"path": "detect_secrets.filters.heuristic.is_indirect_reference"}, {"path": "detect_secrets.filters.heuristic.is_likely_id_string"}, {"path": "detect_secrets.filters.heuristic.is_lock_file"}, {"path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"}, {"path": "detect_secrets.filters.heuristic.is_potential_uuid"}, {"path": "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"}, {"path": "detect_secrets.filters.heuristic.is_sequential_string"}, {"path": "detect_secrets.filters.heuristic.is_swagger_file"}, {"path": "detect_secrets.filters.heuristic.is_templated_secret"}], "results": {}, "generated_at": "2023-01-01T00:00:00Z"}' > .secrets.baseline
fi

# Vérifier si requirements.txt existe, sinon créer un fichier minimal
if [ ! -f requirements.txt ]; then
    echo "📝 Création d'un fichier requirements.txt minimal"
    echo "Flask==2.0.1
pytest==7.0.0
pytest-cov==4.1.0" > requirements.txt
fi

# Créer un simple fichier Python de test si aucun n'existe
if [ ! -f app.py ]; then
    echo "📝 Création d'un fichier app.py minimal pour les tests"
    cat > app.py << 'EOF'
def add(a, b):
    """Add two numbers and return the result."""
    return a + b

def subtract(a, b):
    """Subtract b from a and return the result."""
    return a - b

if __name__ == "__main__":
    print("Simple math functions")
EOF
fi

# Créer un fichier de test minimal
if [ ! -f test_app.py ]; then
    echo "📝 Création d'un fichier test_app.py minimal"
    cat > test_app.py << 'EOF'
import pytest
from app import add, subtract

def test_add():
    """Test the add function."""
    assert add(1, 2) == 3
    assert add(-1, 1) == 0
    assert add(-1, -1) == -2

def test_subtract():
    """Test the subtract function."""
    assert subtract(3, 2) == 1
    assert subtract(2, 3) == -1
    assert subtract(-1, -1) == 0
EOF
fi

# Créer un fichier .gitignore standard pour Python
if [ ! -f .gitignore ]; then
    echo "📝 Création d'un fichier .gitignore pour Python"
    cat > .gitignore << 'EOF'
# Environments
venv/
env/
ENV/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/

# Jupyter Notebook
.ipynb_checkpoints

# VS Code
.vscode/

# PyCharm
.idea/

# Sonar
.scannerwork/

# Jenkins
bandit-results.json
EOF
fi

echo "✅ Configuration de l'environnement terminée avec succès!"
