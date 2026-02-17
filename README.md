# ThreatAnalyzer - Analizador de Amenazas Digitales

Herramienta de análisis forense para detectar URLs, SMS y E-Mails maliciosos mediante análisis de dominios, verificación SSL, análisis de reputación de URLs (URLScan.io, Google Safe Browsing, PhishTank, AbuseIPDB), análisis de reputación telefónica (ListaSpam), análisis de IA con Google AI (Gemma 3) y detección de patrones sospechosos.

## 🚀 Características

- ✅ Análisis de URLs individuales
- ✅ Análisis forense de emails (con buzón temporal integrado)
- ✅ Análisis de SMS (Smishing)
- ✅ Verificación SSL/TLS
- ✅ Consulta WHOIS
- ✅ Análisis de reputación de URLs con múltiples servicios gratuitos: URLScan.io, Google Safe Browsing, PhishTank, AbuseIPDB
- ✅ Reputación telefónica vía ListaSpam (con evasión de fingerprint TLS)
- ✅ **Análisis de IA con Google AI (Gemma 3)** - Detecta patrones sospechosos y calcula nivel de riesgo con razonamiento detallado
- ✅ **Cálculo de riesgo global** que incorpora el análisis de IA en todas las secciones (URLs, emails, SMS)
- ✅ Detección de patrones sospechosos
- ✅ Rate limiting para prevenir abusos
- ✅ Sanitización avanzada de HTML
- ✅ **Sistema de caché SQLite persistente** - Los análisis se guardan en base de datos local para persistencia entre sesiones
- ✅ **Switch de caché en la interfaz** - Controla si se usa la caché para consultas (siempre guarda resultados nuevos)

## 📋 Requisitos

- Python 3.8 o superior
- API Keys de servicios gratuitos (recomendado: Google Safe Browsing)
- **Google AI API Key** (recomendado para análisis de IA) - Obtener en: https://aistudio.google.com/

## 🔧 Instalación

1. Clonar o descargar el repositorio
2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Configurar variables de entorno:
```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar .env con tus configuraciones
# IMPORTANTE: Configurar al menos una API key de los servicios de análisis (recomendado: Google Safe Browsing)
```

## ⚙️ Configuración

Edita el archivo `.env` con tus configuraciones. Las variables más importantes son:

- `RATE_LIMIT_PER_MINUTE`: Límite de peticiones por minuto por IP (default: 30)
- `LOG_LEVEL`: Nivel de logging (INFO, DEBUG, WARNING, ERROR)
- `GOOGLE_AI_API_KEY`: API Key de Google AI Studio para análisis de IA (recomendado)
- `GOOGLE_AI_MODEL`: Modelo de IA a usar (default: gemma-3-27b-it)
- `CACHE_DB_PATH`: Ruta del archivo de base de datos SQLite para la caché (default: cache.db)

### 🤖 Análisis de IA con Google AI

El sistema utiliza Google AI Studio (Gemma 3) para realizar análisis inteligente de contenido:

- **Análisis contextual**: Analiza URLs, emails y SMS para detectar patrones sospechosos
- **Cálculo de riesgo**: Proporciona un score de riesgo (0-100%) con nivel de confianza
- **Razonamiento detallado**: Explica por qué un contenido es sospechoso o seguro
- **Integración global**: El riesgo detectado por la IA se incorpora automáticamente en el cálculo del riesgo global

**Configuración:**
- `GOOGLE_AI_API_KEY`: API Key de Google AI Studio (obligatorio para análisis de IA)
- `GOOGLE_AI_MODEL`: Modelo a usar (default: gemma-3-27b-it)
- Obtener API Key en: https://aistudio.google.com/

### 🔄 Servicios de Análisis de URLs (Gratuitos)

El sistema utiliza múltiples servicios gratuitos para analizar la reputación de URLs:

- **URLScan.io**: Escaneo de URLs (100 escaneos/día sin API key, más con cuenta gratuita)
  - Configurar: `URLSCAN_API_KEY` (opcional)
  
- **Google Safe Browsing**: Base de datos de Google (10,000 consultas/día gratis)
  - Configurar: `GOOGLE_SAFE_BROWSING_API_KEY` (recomendado)
  - Obtener en: https://console.cloud.google.com/apis/credentials
  
- **PhishTank**: Base de datos de phishing (gratis, funciona sin API key)
  - Configurar: `PHISHTANK_API_KEY` (opcional)
  
- **AbuseIPDB**: Reputación de IPs/dominios (1,000 consultas/día gratis)
  - Configurar: `ABUSEIPDB_API_KEY` (opcional)

Configurar servicios habilitados: `ENABLED_ALTERNATIVES=urlscan,googlesb,phishtank`

Ver `.env.example` para todas las opciones disponibles.

## 🏃 Uso

### Desarrollo
```bash
python app.py
```

La aplicación estará disponible en `http://localhost:5000`

### Producción

Para producción, se recomienda usar un servidor WSGI como Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 🔒 Seguridad

- **Rate Limiting**: Implementado con flask-limiter para prevenir abusos
- **Sanitización HTML**: Usa bleach para eliminar scripts y contenido malicioso
- **Validación de entrada**: Todos los inputs son validados y sanitizados
- **Variables de entorno**: Las API keys y configuraciones sensibles se cargan desde `.env`

## 📝 Notas Importantes

1. **Servicios de Análisis**: El sistema combina resultados de múltiples servicios gratuitos:
   - **URLScan.io**: Escaneo detallado de URLs (100 escaneos/día sin API key)
   - **Google Safe Browsing**: Base de datos de Google (10,000 consultas/día gratis) - **Recomendado**
   - **PhishTank**: Base de datos de phishing (gratis, funciona sin API key)
   - **AbuseIPDB**: Reputación de IPs/dominios (1,000 consultas/día gratis)
   - Los resultados se combinan para proporcionar un análisis completo

2. **ListaSpam**: El proyecto usa `curl_cffi` para evadir el fingerprint TLS, lo cual es imprescindible para acceder a ListaSpam.

3. **Rate Limiting**: Por defecto se permite 30 peticiones por minuto por IP. Ajusta según tus necesidades.

4. **Sanitización HTML**: El contenido HTML se sanitiza automáticamente antes de procesar para prevenir XSS y otros ataques.

5. **Sistema de Caché SQLite Persistente**: 
   - Los análisis se guardan en una base de datos SQLite local (`cache.db` por defecto)
   - La caché persiste entre sesiones, permitiendo reutilizar análisis previos
   - **Switch de caché en la interfaz**: Puedes activar/desactivar el uso de la caché desde la interfaz web
   - Cuando la caché está **activada**: Se consulta la caché antes de analizar y siempre se guardan los resultados
   - Cuando la caché está **desactivada**: No se consulta la caché, pero se siguen guardando resultados nuevos o más actuales para futuras sesiones
   - Esto permite tener persistencia de datos incluso cuando prefieres análisis frescos

6. **Análisis de IA**: El sistema utiliza Google AI (Gemma 3) para analizar el contenido y detectar patrones sospechosos. El riesgo calculado por la IA se incorpora automáticamente en el cálculo del riesgo global, asegurando que las amenazas detectadas por la IA se reflejen correctamente en el medidor de riesgo.

## 🛠️ Tecnologías Utilizadas

- Flask: Framework web
- BeautifulSoup: Parsing HTML
- curl_cffi: Evasión de fingerprint TLS
- bleach: Sanitización HTML
- flask-limiter: Rate limiting
- python-dotenv: Gestión de variables de entorno
- SQLite: Base de datos para caché persistente
- Google AI Studio (Gemma 3): Análisis de IA para detección de amenazas
- URLScan.io, Google Safe Browsing, PhishTank, AbuseIPDB: Servicios de análisis de URLs (gratuitos)
- ListaSpam: Reputación telefónica

## 📄 Licencia

Este proyecto está destinado para uso de auditoría y pentesting.

## ⚠️ Disclaimer

Esta herramienta es para uso legítimo de seguridad y análisis. El uso indebido es responsabilidad del usuario.