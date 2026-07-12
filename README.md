# Phishing Detector — URL & Email Analysis

Herramienta CLI en Python para detectar phishing en URLs y archivos `.eml`.

## Instalación

```bash
git clone https://github.com/Shadow-King-Cyber/Phishing-Detector.git
cd Phishing-Detector
pip install -r requirements.txt
```

## Uso

### Analizar una URL

```bash
python -m phishing_detector url "http://ejemplo-sospechoso.xyz/login"
```

### Analizar un email (.eml)

```bash
python -m phishing_detector email correo.eml
```

### Salida en JSON

```bash
python -m phishing_detector url "http://..." --json
python -m phishing_detector email correo.eml --json
```

### Con API keys (reputación)

```bash
python -m phishing_detector url "http://..." --vt-key TU_VT_KEY --pt-key TU_PT_KEY
```

### Clasificador ML (opcional)

```python
from phishing_detector.classifier import PhishingClassifier

clf = PhishingClassifier()
clf.train(urls, labels)  # labels: 1=phishing, 0=legit
result = clf.predict("http://...")
print(result.prediction, result.probability_phishing)
```

## Módulos

### Analizador de URLs

| Feature | Descripción |
|---|---|
| Longitud | URLs >75 chars son sospechosas |
| IP en dominio | Detecta URLs con IP literal |
| Levenshtein | Typosquatting contra 29 dominios conocidos |
| Subdominios | Exceso de subdominios (>3) |
| TLDs sospechosos | `.xyz`, `.tk`, `.top`, `.club`, etc. |
| Caracteres especiales | Símbolos inusuales en URL |
| @ symbol | Ofuscación de credenciales |
| Reputación | VirusTotal v3 + PhishTank API |

Score de riesgo: **0-100** (low / medium / high)

### Analizador de Emails

- Headers **SPF**, **DKIM**, **DMARC** — detecta fallos y inconsistencias
- **Reply-To** distinto de From
- Extracción de links y adjuntos
- Detección de ingeniería social:
  - Urgencia ("act now", "expires today")
  - Amenazas ("account suspended", "legal action")
  - Solicitud de credenciales ("verify your password")
  - Estafas de recompensa ("you have won")
  - Impersonación ("dear account holder")
  - Patrones sospechosos (SSN, tarjetas, transferencias)

## Estructura

```
phishing_detector/
├── cli.py                        # Entry point CLI
├── report.py                     # Formateo de reportes
├── url_analyzer/
│   ├── feature_extractor.py      # Extracción de features
│   ├── reputation.py             # VirusTotal + PhishTank
│   └── scorer.py                 # Scoring 0-100
├── email_analyzer/
│   ├── parser.py                 # Parser de .eml
│   └── social_engineering.py     # Detección de ingeniería social
└── classifier/
    └── model.py                  # Clasificador scikit-learn
```

## Variables de entorno

| Variable | Descripción |
|---|---|
| `VT_API_KEY` | API key de VirusTotal |
| `PHISHTANK_API_KEY` | API key de PhishTank |

También se pueden pasar por CLI con `--vt-key` y `--pt-key`.

## Licencia

[MIT](LICENSE)
