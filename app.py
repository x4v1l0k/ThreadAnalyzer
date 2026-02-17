import os
import ssl
import socket
import datetime
import requests
import tldextract
import logging
import hashlib
import json
import sqlite3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dateutil.relativedelta import relativedelta
from spellchecker import SpellChecker
import re
from bs4 import BeautifulSoup
from curl_cffi import requests as curl_requests
from collections import OrderedDict
from dotenv import load_dotenv
import bleach

# Cargar variables de entorno desde .env
load_dotenv()

# Configurar logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configurar Rate Limiting
rate_limit_per_minute = int(os.getenv('RATE_LIMIT_PER_MINUTE', '30'))
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{rate_limit_per_minute} per minute"],
    storage_uri="memory://"
)

# Cabeceras globales para peticiones externas
USER_AGENT = os.getenv('USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36')
HEADERS = {
    'accept': 'application/json',
    'user-agent': USER_AGENT
}

# Configuración de API Keys de VirusTotal (múltiples keys separadas por comas)
VT_API_KEYS_STR = os.getenv("VT_API_KEYS", os.getenv("VT_API_KEY", ""))
VT_API_KEYS = [key.strip() for key in VT_API_KEYS_STR.split(',') if key.strip()] if VT_API_KEYS_STR else []

# Configuración de servicios de análisis de URLs (alternativas gratuitas)
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")  # Opcional, funciona sin API key

# Habilitar/deshabilitar servicios (separados por comas: urlscan,googlesb,abuseipdb,phishtank)
ENABLED_ALTERNATIVES = [s.strip().lower() for s in os.getenv("ENABLED_ALTERNATIVES", "urlscan,googlesb,phishtank").split(',') if s.strip()]

# ============================================================================
# GESTIÓN DE CUOTAS Y RATE LIMITING POR SERVICIO
# ============================================================================

import threading

class QuotaManager:
    """Gestor de cuotas para servicios de API con límites por minuto, hora y día"""
    def __init__(self, name, limits_per_minute, limits_per_hour, limits_per_day):
        self.name = name
        self.limits_per_minute = limits_per_minute
        self.limits_per_hour = limits_per_hour
        self.limits_per_day = limits_per_day
        self.queries_per_minute = []  # Timestamps de consultas en el último minuto
        self.queries_per_hour = []    # Timestamps de consultas en la última hora
        self.queries_per_day = []     # Timestamps de consultas en el último día
        self.lock = threading.Lock()
        self.last_day_reset = datetime.datetime.now().date()
    
    def _clean_old_queries(self):
        """Limpia consultas antiguas de las listas"""
        now = datetime.datetime.now()
        
        # Limpiar consultas de más de 1 minuto
        self.queries_per_minute[:] = [t for t in self.queries_per_minute 
                                      if (now - t).total_seconds() < 60]
        
        # Limpiar consultas de más de 1 hora
        self.queries_per_hour[:] = [t for t in self.queries_per_hour 
                                   if (now - t).total_seconds() < 3600]
        
        # Limpiar consultas de más de 1 día y resetear si cambió el día
        today = now.date()
        if today != self.last_day_reset:
            self.queries_per_day.clear()
            self.last_day_reset = today
        else:
            self.queries_per_day[:] = [t for t in self.queries_per_day 
                                       if (now - t).total_seconds() < 86400]
    
    def can_query(self):
        """Verifica si se puede hacer una consulta respetando los límites"""
        with self.lock:
            self._clean_old_queries()
            
            if len(self.queries_per_minute) >= self.limits_per_minute:
                return False, "minute"
            if len(self.queries_per_hour) >= self.limits_per_hour:
                return False, "hour"
            if len(self.queries_per_day) >= self.limits_per_day:
                return False, "day"
            
            return True, None
    
    def record_query(self):
        """Registra una consulta realizada"""
        with self.lock:
            now = datetime.datetime.now()
            self.queries_per_minute.append(now)
            self.queries_per_hour.append(now)
            self.queries_per_day.append(now)
            self._clean_old_queries()
    
    def get_remaining(self):
        """Obtiene las consultas restantes en cada período"""
        with self.lock:
            self._clean_old_queries()
            return {
                "minute": max(0, self.limits_per_minute - len(self.queries_per_minute)),
                "hour": max(0, self.limits_per_hour - len(self.queries_per_hour)),
                "day": max(0, self.limits_per_day - len(self.queries_per_day))
            }

# Inicializar gestores de cuotas para cada servicio
# URLScan.io: Public Scans - 60/min, 500/hora, 5000/día
URLSCAN_QUOTA = QuotaManager("URLScan.io", limits_per_minute=60, limits_per_hour=500, limits_per_day=5000)

# Google Safe Browsing: 10,000 consultas/día (sin límites por minuto/hora específicos, usar valores conservadores)
# Asumiendo distribución uniforme: ~166/hora, ~2.7/minuto (usaremos 2/min para ser conservadores)
GOOGLE_SB_QUOTA = QuotaManager("Google Safe Browsing", limits_per_minute=2, limits_per_hour=166, limits_per_day=10000)

# AbuseIPDB: check endpoint - 1000/día (sin límites por minuto/hora específicos)
# Distribución: 1000/día = ~41/hora = ~0.7/minuto
# Pero para análisis en batch, permitimos más consultas por minuto (hasta 10)
# El límite diario de 1000 se mantendrá
ABUSEIPDB_QUOTA = QuotaManager("AbuseIPDB", limits_per_minute=10, limits_per_hour=100, limits_per_day=1000)

# PhishTank: Sin límites conocidos, pero usaremos valores conservadores para evitar abusos
PHISHTANK_QUOTA = QuotaManager("PhishTank", limits_per_minute=10, limits_per_hour=100, limits_per_day=1000)

# ============================================================================
# GESTIÓN DE VIRUSTOTAL (SISTEMA ORIGINAL)
# ============================================================================

# Estructura para manejar API keys de VirusTotal y sus ratios
class VTAPIKey:
    def __init__(self, key, index):
        self.key = key
        self.index = index
        self.queries_per_minute = 0
        self.queries_per_day = 0
        self.queries_per_month = 0
        self.remaining_minute = 0
        self.remaining_day = 0
        self.remaining_month = 0
        self.last_ratio_check = None
        self.is_active = True
        self.query_times = []  # Timestamps de consultas para rate limiting por minuto
        self.error_count = 0  # Contador de errores consecutivos
        
    def get_priority_score(self):
        """
        Calcula un score de prioridad basado en el ratio disponible.
        Mayor score = más disponible = mejor para usar primero
        """
        if not self.is_active:
            return -1  # Keys inactivas tienen prioridad negativa
        
        # Priorizar por ratio disponible (minuto > día > mes)
        score = 0
        if self.remaining_minute > 0:
            score += self.remaining_minute * 1000  # Más peso a ratio por minuto
        if self.remaining_day > 0:
            score += self.remaining_day * 10  # Menos peso a ratio por día
        if self.remaining_month > 0:
            score += self.remaining_month  # Menos peso a ratio por mes
        
        return score
    
    def can_query(self, rate_limit_per_minute):
        """Verifica si se puede hacer una consulta con esta key"""
        if not self.is_active:
            return False
        
        now = datetime.datetime.now()
        # Limpiar consultas antiguas (> 1 minuto)
        self.query_times[:] = [t for t in self.query_times if (now - t).total_seconds() < 60]
        
        # Verificar límites
        if len(self.query_times) >= rate_limit_per_minute:
            return False
        if self.remaining_minute <= 0 and self.remaining_day <= 0 and self.remaining_month <= 0:
            return False
        
        return True
    
    def record_query(self):
        """Registra una consulta realizada"""
        now = datetime.datetime.now()
        self.query_times.append(now)
        if self.remaining_minute > 0:
            self.remaining_minute -= 1
        if self.remaining_day > 0:
            self.remaining_day -= 1
        if self.remaining_month > 0:
            self.remaining_month -= 1
        self.error_count = 0  # Resetear contador de errores en éxito

# Inicializar lista de API keys
VT_API_KEY_OBJECTS = []
for idx, key in enumerate(VT_API_KEYS):
    VT_API_KEY_OBJECTS.append(VTAPIKey(key, idx))
    logger.info(f"API Key de VirusTotal #{idx+1} configurada (primeros 10 chars: {key[:10]}...)")

if not VT_API_KEY_OBJECTS:
    logger.warning("No hay API Keys de VirusTotal configuradas. Se usarán alternativas gratuitas.")

# Rate limiting para VirusTotal (4 consultas por minuto por defecto)
VT_RATE_LIMIT = int(os.getenv('VT_RATE_LIMIT_PER_MINUTE', '4'))
VT_LOCK = threading.Lock()  # Lock para sincronizar acceso a las API keys

# Configuración de Google AI Studio (Gemma 3)
GOOGLE_AI_API_KEY = os.getenv("GOOGLE_AI_API_KEY", "")
GOOGLE_AI_MODEL = os.getenv("GOOGLE_AI_MODEL", "gemma-3-27b-it")  # Modelo Gemma 3
GOOGLE_AI_TIMEOUT = int(os.getenv("GOOGLE_AI_TIMEOUT", "30"))
if not GOOGLE_AI_API_KEY:
    logger.warning("GOOGLE_AI_API_KEY no configurada. El análisis de IA estará deshabilitado.")

# Caché simple en memoria para WHOIS (evita redundancia y bloqueos por IPs de WHOIS)
# Usa OrderedDict para mantener orden y limitar tamaño (LRU cache simple)
WHOIS_CACHE = OrderedDict()
MAX_CACHE_SIZE = int(os.getenv('MAX_CACHE_SIZE', '1000'))  # Límite máximo de entradas en caché

# Caché para análisis completos (URLs, emails, SMS)
ANALYSIS_CACHE = OrderedDict()
MAX_ANALYSIS_CACHE_SIZE = int(os.getenv('MAX_ANALYSIS_CACHE_SIZE', '500'))  # Límite máximo de análisis cacheados

# Caché para resultados de AbuseIPDB por IP (evita consultas duplicadas)
ABUSEIPDB_CACHE = OrderedDict()
MAX_ABUSEIPDB_CACHE_SIZE = int(os.getenv('MAX_ABUSEIPDB_CACHE_SIZE', '200'))  # Límite máximo de IPs cacheadas

# Estado del switch de caché (por defecto activado)
CACHE_ENABLED = True

# Configuración de SQLite para caché persistente
CACHE_DB_PATH = os.getenv('CACHE_DB_PATH', 'cache.db')

# Timeouts configurables
TIMEOUT_SSL = int(os.getenv('TIMEOUT_SSL', '5'))
TIMEOUT_HTTP = int(os.getenv('TIMEOUT_HTTP', '10'))
TIMEOUT_VIRUSTOTAL = int(os.getenv('TIMEOUT_VIRUSTOTAL', '15'))
TIMEOUT_ALTERNATIVES = int(os.getenv('TIMEOUT_ALTERNATIVES', '10'))

# Límites de tamaño
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', '2048'))
MAX_EMAIL_SIZE_MB = int(os.getenv('MAX_EMAIL_SIZE_MB', '10'))
MAX_SMS_LENGTH = int(os.getenv('MAX_SMS_LENGTH', '10000'))
MAX_WORDS_FOR_SPELLCHECK = int(os.getenv('MAX_WORDS_FOR_SPELLCHECK', '500'))

# Configuración de Mail.tm
MAIL_TM_URL = os.getenv('MAIL_TM_URL', 'https://api.mail.tm')

# Configuración de sanitización HTML con bleach
# Permitir solo etiquetas y atributos seguros para análisis
ALLOWED_TAGS = ['a', 'p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title'],
    '*': ['class', 'id']
}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

# Lista masiva de dominios de confianza (NO se analizan para evitar ruido)
# NOTA: NO incluir aquí trackers (mandrill, sendgrid, t.co) porque queremos seguir sus redirecciones.
TRUSTED_DOMAINS = [
    'google.com', 'googleusercontent.com', 'microsoft.com', 'outlook.com', 
    'live.com', 'apple.com', 'w3.org', 'cloudfront.net', 'gstatic.com', 
    'googleapis.com', 'schema.org', 'klaviyo.com', 'facebook.com', 'instagram.com',
    'gmail.com', 'twitter.com', 'linkedin.com', 'whatsapp.com', 'youtube.com',
    'amazon.com', 'aws.amazon.com', 'github.com', 'githubusercontent.com',
    'bitbucket.org', 'gitlab.com', 'dropbox.com', 'slack.com', 'zoom.us',
    'adobe.com', 'salesforce.com', 'hubspot.com', 'mailchimp.com', 'zendesk.com',
    'intercom.io', 'stripe.com', 'paypal.com', 'visa.com', 'mastercard.com',
    'prosegur.com', 'prosegur.es', 'office.com', 'office365.com', 'azure.com',
    'bing.com', 'yahoo.com', 'icloud.com', 'apple-cloudkit.com', 'mzstatic.com',
    'fbcdn.net', 'twimg.com', 'doubleclick.net', 'google-analytics.com', 
    'googletagmanager.com', 'vimeo.com', 'wordpress.org', 'wordpress.com', 
    'gravatar.com', 'jquery.com', 'bootstrapcdn.com', 'font-awesome.com', 
    'fontawesome.com', 'typekit.net', 'googlefonts.com', 'pinterest.com', 
    'tiktok.com', 'snapchat.com', 'reddit.com', 'medium.com', 'spotify.com', 
    'netflix.com', 'ebay.com', 'booking.com', 'airbnb.com',
    # Dominios adicionales de CDN/Cloud
    'amazonaws.com', 's3.amazonaws.com', 'cloudflare.com', 'cloudflare.net', 
    'cdn.cloudflare.net', 'fastly.com', 'fastly.net', 'cdnjs.cloudflare.com',
    'jsdelivr.net', 'cdn.jsdelivr.net', 'akamai.net', 'akamaiedge.net', 
    'akamaihd.net', 'edgecastcdn.net', 'edgekey.net',
    # Dominios adicionales de empresas tecnológicas
    'microsoftonline.com', 'facebook.net', 't.co', 'ytimg.com', 'googlevideo.com',
    'cdninstagram.com', 'googlemail.com', 'hotmail.com', 'ymail.com', 'aol.com',
    # Servicios adicionales
    'stackoverflow.com', 'stackexchange.com', 'redd.it', 'wikipedia.org', 
    'wikimedia.org', 'wp.com', 'tumblr.com', 'box.com', 'onedrive.com',
    'adobecloud.com', 'discord.com', 'discordapp.com', 'twitch.tv',
    'soundcloud.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'aliexpress.com',
    'shopify.com', 'myshopify.com', 'wix.com', 'wixsite.com', 'squarespace.com',
    'weebly.com', 'cloudflare-dns.com'
]

# Convertir a set para búsqueda más rápida
TRUSTED_DOMAINS_SET = set(domain.lower() for domain in TRUSTED_DOMAINS)

def is_trusted_domain(domain):
    """
    Verifica si un dominio está en la lista de dominios de confianza.
    Retorna True si el dominio o su dominio base está en la whitelist.
    """
    if not domain:
        return False
    
    domain_lower = domain.lower().strip()
    
    # Verificar dominio exacto
    if domain_lower in TRUSTED_DOMAINS_SET:
        return True
    
    # Verificar dominio base (sin subdominios)
    try:
        extracted = tldextract.extract(domain_lower)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        if base_domain in TRUSTED_DOMAINS_SET:
            return True
    except:
        pass
    
    return False

# Servicios conocidos de hosting que pueden alojar contenido malicioso
HOSTING_SERVICES = [
    'googleusercontent.com', 'storage.googleapis.com', 'dropboxusercontent.com', 
    'firebaseapp.com', 'githubusercontent.com', 's3.amazonaws.com', 'visualstudio.com'
]

# Spellchecker bilingüe (ignora palabras válidas en ES o EN)
spell_es = SpellChecker(language='es')
spell_en = SpellChecker(language='en')

def get_ssl_info(hostname):
    if not hostname or not isinstance(hostname, str):
        return {"error": "Hostname inválido", "status": "No SSL/Error"}
    
    # Limpiar hostname
    hostname = hostname.strip().lower()
    
    # Validar longitud
    if len(hostname) > 255:
        return {"error": "Hostname demasiado largo", "status": "No SSL/Error"}
    
    try:
        logger.debug(f"Verificando SSL para: {hostname}")
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT_SSL) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                
                is_expired = datetime.datetime.now(datetime.timezone.utc) > not_after
                remaining_days = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
                
                status = "Secure" if not is_expired else "Expired"
                if is_expired:
                    logger.warning(f"Certificado SSL expirado para {hostname}")
                elif remaining_days < 30:
                    logger.warning(f"Certificado SSL expira pronto para {hostname} ({remaining_days} días)")
                
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before.strftime("%Y-%m-%d"),
                    "valid_to": not_after.strftime("%Y-%m-%d"),
                    "is_expired": is_expired,
                    "remaining_days": remaining_days,
                    "status": status
                }
    except socket.gaierror as e:
        logger.error(f"Error DNS para {hostname}: {str(e)}")
        return {"error": f"Error DNS: {str(e)}", "status": "No SSL/Error"}
    except socket.timeout:
        logger.error(f"Timeout conectando a {hostname}:443")
        return {"error": "Timeout al conectar", "status": "No SSL/Error"}
    except ssl.SSLError as e:
        logger.debug(f"Error SSL para {hostname}: {str(e)}")
        return {"error": f"Error SSL: {str(e)}", "status": "No SSL/Error"}
    except ConnectionResetError as e:
        # El servidor cerró la conexión - esto es común y no es un error crítico
        logger.debug(f"Conexión cerrada por el servidor para {hostname}: {str(e)}")
        return {"error": "Conexión cerrada por el servidor", "status": "No SSL/Error"}
    except OSError as e:
        # Errores de red comunes (10054, etc.) - no son críticos
        if "10054" in str(e) or "forzado" in str(e).lower() or "interrupción" in str(e).lower():
            logger.debug(f"Conexión interrumpida para {hostname}: {str(e)}")
        else:
            logger.warning(f"Error de red para {hostname}: {str(e)}")
        return {"error": "Error de conexión", "status": "No SSL/Error"}
    except Exception as e:
        logger.warning(f"Error verificando SSL para {hostname}: {str(e)}")
        return {"error": str(e), "status": "No SSL/Error"}

def get_domain_age(domain):
    # Validar dominio antes de procesar
    if not domain or not isinstance(domain, str) or len(domain) > 255:
        logger.warning(f"Dominio inválido para WHOIS: {domain}")
        return {"error": "Dominio inválido", "is_recent": False}
    
    # Limpiar dominio
    domain = domain.strip().lower()
    
    # Verificar caché (mover al final para LRU)
    if domain in WHOIS_CACHE:
        # Mover al final (más reciente)
        result = WHOIS_CACHE.pop(domain)
        WHOIS_CACHE[domain] = result
        logger.debug(f"WHOIS cache hit para: {domain}")
        return result

    try:
        logger.info(f"Buscando WHOIS para: {domain}")
        import whois
        w = whois.whois(domain)
        
        if not w:
            logger.warning(f"Sin datos WHOIS para: {domain}")
            return {"error": "Sin datos WHOIS", "is_recent": False}
            
        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if isinstance(creation_date, str):
                try:
                    import dateutil.parser
                    creation_date = dateutil.parser.parse(creation_date)
                except Exception as parse_error:
                    logger.warning(f"Error parseando fecha WHOIS: {parse_error}")
                    pass
            
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                now = datetime.datetime.now(creation_date.tzinfo)
            else:
                now = datetime.datetime.now()
                
            age = relativedelta(now, creation_date)
            years = age.years
            months = age.months
            is_recent = (years == 0 and months < 6)
            
            result = {
                "creation_date": creation_date.strftime("%Y-%m-%d") if hasattr(creation_date, 'strftime') else str(creation_date),
                "age_years": years,
                "age_months": months,
                "is_recent": is_recent,
                "registrar": w.get('registrar', 'N/A')
            }
            
            # Agregar al caché con límite LRU
            if len(WHOIS_CACHE) >= MAX_CACHE_SIZE:
                # Eliminar el más antiguo (primero en OrderedDict)
                WHOIS_CACHE.popitem(last=False)
            WHOIS_CACHE[domain] = result
            
            logger.info(f"WHOIS obtenido para {domain}: {years}a {months}m")
            return result
        logger.warning(f"No se encontró fecha de creación para: {domain}")
        return {"error": "No creation date found", "is_recent": False}
    except Exception as e:
        logger.error(f"WHOIS Error para {domain}: {str(e)}", exc_info=True)
        return {"error": str(e), "is_recent": False}

def check_phone_reputation(phone):
    if not phone or not isinstance(phone, str):
        return None
    try:
        clean_phone = re.sub(r'\D', '', phone)
        if len(clean_phone) < 9 or len(clean_phone) > 15:  # Validar longitud razonable
            logger.warning(f"Número de teléfono inválido: {phone}")
            return None

        url = f"https://www.listaspam.com/busca.php?Telefono={clean_phone}"
        logger.info(f"Consultando ListaSpam para: {clean_phone}")
        
        # Bypass 403 usando curl_cffi para impersonar Chrome (imprescindible para evadir fingerprint TLS)
        res = curl_requests.get(url, impersonate="chrome110", timeout=TIMEOUT_HTTP)

        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = soup.get_text()
            
            # --- 1. Valoración Global ---
            rating_div = soup.select_one('.phone_rating')
            rating_text = rating_div.get('title', 'Sin valoración') if rating_div else "Sin valoración"
            if "global:" in rating_text:
                rating_text = rating_text.split("global:")[1].strip()
            # Fallback
            if rating_text == "Sin valoración" and "peligroso" in page_text.lower():
                rating_text = "Peligroso"

            # --- 2. Denuncias ---
            reports_box = soup.select_one('.n_reports .result')
            reports_text = reports_box.get_text(strip=True) if reports_box else "0"
            if reports_text == "0":
                m = re.search(r'(\d+)\s+denuncias', page_text.lower())
                reports_int = int(m.group(1)) if m else 0
            else:
                reports_int = int(re.sub(r'\D', '', reports_text))

            # --- 3. Búsquedas ---
            search_box = soup.select_one('.n_search .result')
            search_val = search_box.get_text(strip=True) if search_box else "0"
            
            # --- 4. Etiquetas ---
            tags_box = soup.select_one('.tag_cloud')
            tags_text = "Ninguna"
            if tags_box:
                tags_content = tags_box.get_text(separator=' ', strip=True)

                if "son:" in tags_content:
                    tags_text = tags_content.split("son:")[1].strip()
                else:
                    tags_text = tags_content

                # Buscar pares: texto + número
                pairs = re.findall(r'([A-Za-zÁÉÍÓÚÜÑáéíóúüñ]+)\s+(\d+)', tags_text)

                # Formatear resultado
                tags_text = ', '.join(f'{name} ({count})' for name, count in pairs)

            result = {
                "status": rating_text,
                "reports": reports_int,
                "searches": search_val,
                "tags": tags_text[:150],
                "url": url
            }
            logger.info(f"ListaSpam: {clean_phone} - {rating_text} ({reports_int} denuncias)")
            return result
        else:
            logger.warning(f"ListaSpam retornó código {res.status_code} para {clean_phone}")
    except Exception as e:
        logger.error(f"Error parseando ListaSpam vía curl_cffi: {str(e)}", exc_info=True)
    return None

# ============================================================================
# VIRUSTOTAL (SISTEMA ORIGINAL)
# ============================================================================

def check_vt_api_ratios(api_key_obj):
    """
    Consulta el ratio disponible de una API key de VirusTotal.
    Si el endpoint de quotas no está disponible (403), asume que la key está activa
    y solo verificará cuando reciba un 429 (rate limit).
    """
    try:
        headers = {"x-apikey": api_key_obj.key}
        
        # Intentar obtener el user ID primero
        user_response = requests.get("https://www.virustotal.com/api/v3/users/me", 
                                    headers=headers, timeout=5)
        
        user_id = None
        if user_response.status_code == 200:
            user_data = user_response.json()
            user_id = user_data.get('data', {}).get('id')
        
        # Si tenemos user_id, usar endpoint específico, sino usar /me
        if user_id:
            quota_url = f"https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
        else:
            quota_url = "https://www.virustotal.com/api/v3/users/me/overall_quotas"
        
        response = requests.get(quota_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            quotas = data.get('data', {})
            
            # La estructura puede variar, intentar múltiples formatos
            # Formato 1: api_requests_hourly.user.allowed/used
            hourly = quotas.get('api_requests_hourly', {})
            if isinstance(hourly, dict):
                user_hourly = hourly.get('user', {})
                if user_hourly:
                    api_key_obj.remaining_minute = max(0, user_hourly.get('allowed', 0) - user_hourly.get('used', 0))
                else:
                    # Formato alternativo: api_requests_hourly.allowed/used directamente
                    api_key_obj.remaining_minute = max(0, hourly.get('allowed', 0) - hourly.get('used', 0))
            else:
                api_key_obj.remaining_minute = 0
            
            daily = quotas.get('api_requests_daily', {})
            if isinstance(daily, dict):
                user_daily = daily.get('user', {})
                if user_daily:
                    api_key_obj.remaining_day = max(0, user_daily.get('allowed', 0) - user_daily.get('used', 0))
                else:
                    api_key_obj.remaining_day = max(0, daily.get('allowed', 0) - daily.get('used', 0))
            else:
                api_key_obj.remaining_day = 0
            
            monthly = quotas.get('api_requests_monthly', {})
            if isinstance(monthly, dict):
                user_monthly = monthly.get('user', {})
                if user_monthly:
                    api_key_obj.remaining_month = max(0, user_monthly.get('allowed', 0) - user_monthly.get('used', 0))
                else:
                    api_key_obj.remaining_month = max(0, monthly.get('allowed', 0) - monthly.get('used', 0))
            else:
                api_key_obj.remaining_month = 0
            
            api_key_obj.last_ratio_check = datetime.datetime.now()
            api_key_obj.is_active = True
            api_key_obj.error_count = 0
            
            logger.debug(f"VT Key #{api_key_obj.index+1}: min={api_key_obj.remaining_minute}, día={api_key_obj.remaining_day}, mes={api_key_obj.remaining_month}")
            return True
        elif response.status_code == 401:
            # API key inválida
            logger.error(f"VT Key #{api_key_obj.index+1} inválida o expirada")
            api_key_obj.is_active = False
            api_key_obj.error_count = 999  # Marcar como permanentemente inactiva
            return False
        elif response.status_code == 403:
            # El endpoint de quotas requiere permisos especiales (solo disponible en planes premium)
            # Asumir que la key está activa y funcionará hasta que recibamos un 429
            logger.debug(f"VT Key #{api_key_obj.index+1}: endpoint de quotas no disponible (403), asumiendo key activa")
            api_key_obj.remaining_minute = VT_RATE_LIMIT  # Asumir que tiene el límite configurado
            api_key_obj.remaining_day = 1000  # Valor alto para no limitar
            api_key_obj.remaining_month = 10000  # Valor alto para no limitar
            api_key_obj.last_ratio_check = datetime.datetime.now()
            api_key_obj.is_active = True
            api_key_obj.error_count = 0  # No contar como error
            return True
        else:
            logger.warning(f"Error consultando ratio de VT Key #{api_key_obj.index+1}: {response.status_code} - {response.text[:200]}")
            api_key_obj.error_count += 1
            if api_key_obj.error_count >= 3:
                api_key_obj.is_active = False
                logger.error(f"VT Key #{api_key_obj.index+1} desactivada por múltiples errores")
            return False
    except Exception as e:
        logger.warning(f"Error consultando ratio de VT Key #{api_key_obj.index+1}: {str(e)}")
        api_key_obj.error_count += 1
        if api_key_obj.error_count >= 3:
            api_key_obj.is_active = False
        return False

def get_best_vt_api_key():
    """
    Selecciona la mejor API key disponible basándose en ratios y prioridad.
    Retorna el objeto VTAPIKey o None si no hay keys disponibles.
    """
    if not VT_API_KEY_OBJECTS:
        return None
    
    with VT_LOCK:
        now = datetime.datetime.now()
        
        # Actualizar ratios de keys que no se han consultado en los últimos 30 segundos
        for key_obj in VT_API_KEY_OBJECTS:
            if key_obj.last_ratio_check is None or \
               (now - key_obj.last_ratio_check).total_seconds() > 30:
                check_vt_api_ratios(key_obj)
        
        # Filtrar keys activas que pueden hacer consultas
        available_keys = [k for k in VT_API_KEY_OBJECTS 
                         if k.is_active and k.can_query(VT_RATE_LIMIT)]
        
        if not available_keys:
            logger.warning("No hay API keys de VirusTotal disponibles en este momento")
            return None
        
        # Ordenar por prioridad (mayor score primero)
        available_keys.sort(key=lambda k: k.get_priority_score(), reverse=True)
        best_key = available_keys[0]
        
        logger.debug(f"Seleccionada VT Key #{best_key.index+1} (score: {best_key.get_priority_score()}, "
                    f"min: {best_key.remaining_minute}, día: {best_key.remaining_day})")
        
        return best_key

def check_virustotal(url, skip_rate_limit=False, retry_count=0, used_keys=None):
    """
    Consulta VirusTotal para una URL usando el sistema de rotación de API keys.
    skip_rate_limit: Si es True, ignora el rate limit (útil para consultas prioritarias)
    retry_count: Contador interno para evitar recursión infinita
    used_keys: Set de índices de keys ya probadas en esta consulta
    """
    if used_keys is None:
        used_keys = set()
    
    if not VT_API_KEY_OBJECTS:
        logger.warning("No hay API Keys de VirusTotal configuradas")
        return {"status": "Manual Check Required", "message": "API Keys not configured", "malicious": 0, "suspicious": 0, "detections": []}
    
    # Validar URL antes de procesar
    if not url or not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        logger.warning(f"URL inválida para VirusTotal: {url}")
        return {"error": "URL inválida", "malicious": 0, "suspicious": 0, "detections": []}
    
    # Evitar recursión infinita
    if retry_count >= len(VT_API_KEY_OBJECTS):
        logger.error("Se han probado todas las API keys sin éxito")
        return {"error": "Todas las API keys fallaron. Intenta más tarde.", "malicious": 0, "suspicious": 0, "detections": []}
    
    # Obtener la mejor API key disponible (excluyendo las ya probadas)
    api_key_obj = get_best_vt_api_key()
    if not api_key_obj:
        logger.info(f"No hay API keys disponibles. Omitiendo consulta a VirusTotal para: {url[:50]}...")
        return {"status": "Rate Limited", "message": "Todas las API keys han alcanzado su límite. Intenta más tarde.", "malicious": 0, "suspicious": 0, "detections": []}
    
    # Si ya probamos esta key, intentar con otra
    if api_key_obj.index in used_keys:
        # Buscar otra key disponible
        available_keys = [k for k in VT_API_KEY_OBJECTS 
                         if k.is_active and k.index not in used_keys and k.can_query(VT_RATE_LIMIT)]
        if available_keys:
            available_keys.sort(key=lambda k: k.get_priority_score(), reverse=True)
            api_key_obj = available_keys[0]
        else:
            logger.info(f"No hay más API keys disponibles. Omitiendo consulta a VirusTotal para: {url[:50]}...")
            return {"status": "Rate Limited", "message": "Todas las API keys han alcanzado su límite. Intenta más tarde.", "malicious": 0, "suspicious": 0, "detections": []}
    
    used_keys.add(api_key_obj.index)
    
    # Verificar rate limit por minuto de esta key específica
    if not skip_rate_limit and not api_key_obj.can_query(VT_RATE_LIMIT):
        logger.info(f"Rate limit alcanzado para Key #{api_key_obj.index+1}. Omitiendo consulta a VirusTotal para: {url[:50]}...")
        return {"status": "Rate Limited", "message": f"Consulta omitida por límite de rate ({VT_RATE_LIMIT}/min). URL priorizada para siguiente minuto.", "malicious": 0, "suspicious": 0, "detections": []}
    
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key_obj.key}
        logger.debug(f"Consultando VirusTotal con Key #{api_key_obj.index+1} para: {url[:50]}...")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=TIMEOUT_VIRUSTOTAL)
        
        if response.status_code == 200:
            # Registrar consulta exitosa
            api_key_obj.record_query()
            
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            results = data['data']['attributes'].get('last_analysis_results', {})
            
            # Extraer detecciones específicas
            detections = []
            for engine, result in results.items():
                if result.get('category') == 'malicious':
                    detections.append({
                        'engine': engine,
                        'method': result.get('method', 'N/A'),
                        'result': result.get('result', 'Malicious')
                    })
                elif result.get('category') == 'suspicious':
                    detections.append({
                        'engine': engine,
                        'method': result.get('method', 'N/A'),
                        'result': result.get('result', 'Suspicious')
                    })
            
            result = {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "total": sum(stats.values()),
                "detections": detections[:20]  # Limitar a 20 detecciones para no sobrecargar
            }
            if result['malicious'] > 0:
                logger.warning(f"VirusTotal (Key #{api_key_obj.index+1}) detectó {result['malicious']} motores maliciosos para: {url[:50]}")
            return result
        elif response.status_code == 404:
            # 404 no consume cuota, pero registramos la consulta
            api_key_obj.record_query()
            logger.info(f"URL no encontrada en VirusTotal (Key #{api_key_obj.index+1}): {url[:50]}")
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "status": "Clean/New", "message": "URL no encontrada en VT.", "detections": []}
        elif response.status_code == 429:
            # Rate limit alcanzado - marcar key como temporalmente inactiva y rotar
            logger.warning(f"Rate limit excedido para VT Key #{api_key_obj.index+1}. Rotando a siguiente key...")
            api_key_obj.is_active = False
            api_key_obj.error_count += 1
            
            # Intentar con otra key si hay disponibles
            retry_key = get_best_vt_api_key()
            if retry_key and retry_key.index != api_key_obj.index and retry_key.index not in used_keys:
                logger.info(f"Reintentando con VT Key #{retry_key.index+1}...")
                return check_virustotal(url, skip_rate_limit=skip_rate_limit, retry_count=retry_count+1, used_keys=used_keys)
            
            return {"error": "Rate limit excedido en todas las API keys. Intenta más tarde.", "malicious": 0, "suspicious": 0, "detections": []}
        else:
            # Error desconocido - puede ser que la key esté agotada
            api_key_obj.error_count += 1
            if api_key_obj.error_count >= 3:
                api_key_obj.is_active = False
                logger.error(f"VT Key #{api_key_obj.index+1} desactivada por múltiples errores ({response.status_code})")
            
            # Intentar con otra key si hay disponibles
            if response.status_code in [401, 403]:  # Errores de autenticación/autorización
                retry_key = get_best_vt_api_key()
                if retry_key and retry_key.index != api_key_obj.index and retry_key.index not in used_keys:
                    logger.info(f"Error de autenticación con Key #{api_key_obj.index+1}. Reintentando con Key #{retry_key.index+1}...")
                    return check_virustotal(url, skip_rate_limit=skip_rate_limit, retry_count=retry_count+1, used_keys=used_keys)
            
            logger.error(f"Error VirusTotal Key #{api_key_obj.index+1} {response.status_code}: {response.text[:200]}")
            return {"error": f"Error VT {response.status_code}", "malicious": 0, "suspicious": 0, "detections": []}
    except requests.exceptions.Timeout:
        logger.error(f"Timeout consultando VirusTotal Key #{api_key_obj.index+1} para: {url[:50]}")
        # Timeout no debería desactivar la key, solo incrementar error_count
        api_key_obj.error_count += 1
        return {"error": "Timeout al consultar VirusTotal", "malicious": 0, "suspicious": 0, "detections": []}
    except Exception as e:
        logger.error(f"Error consultando VirusTotal Key #{api_key_obj.index+1}: {str(e)}", exc_info=True)
        api_key_obj.error_count += 1
        if api_key_obj.error_count >= 5:
            api_key_obj.is_active = False
            logger.error(f"VT Key #{api_key_obj.index+1} desactivada por demasiados errores")
        return {"error": str(e), "malicious": 0, "suspicious": 0, "detections": []}

# ============================================================================
# SERVICIOS DE ANÁLISIS DE URLS (GRATUITOS - ALTERNATIVAS)
# ============================================================================

def check_urlscan(url):
    """
    Consulta URLScan.io para una URL.
    URLScan.io es gratuito con límites: 60/min, 500/hora, 5000/día (Public Scans).
    """
    if 'urlscan' not in ENABLED_ALTERNATIVES:
        return None
    
    # Verificar cuota antes de consultar
    can_query, limit_type = URLSCAN_QUOTA.can_query()
    if not can_query:
        remaining = URLSCAN_QUOTA.get_remaining()
        logger.debug(f"URLScan.io: Cuota {limit_type} agotada. Restantes: {remaining}")
        return None
    
    try:
        # URLScan requiere primero enviar la URL para escanear
        headers = {
            'Content-Type': 'application/json',
            'API-Key': URLSCAN_API_KEY if URLSCAN_API_KEY else None
        }
        if not URLSCAN_API_KEY:
            headers.pop('API-Key', None)
        
        # Enviar URL para escanear
        scan_data = {
            'url': url,
            'visibility': 'public'
        }
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            json=scan_data,
            headers={k: v for k, v in headers.items() if v is not None},
            timeout=TIMEOUT_ALTERNATIVES
        )
        
        if response.status_code == 200:
            # Registrar cuota solo cuando el scan es exitoso
            URLSCAN_QUOTA.record_query()
            
            scan_result = response.json()
            uuid = scan_result.get('uuid')
            
            if not uuid:
                # Si no hay UUID, intentar buscar resultados existentes
                pass
            else:
                # Intentar obtener resultados (puede que el escaneo aún esté en proceso)
                import time
                max_retries = 3
                for attempt in range(max_retries):
                    time.sleep(1)  # Esperar 1 segundo entre intentos
                    result_response = requests.get(
                        f'https://urlscan.io/api/v1/result/{uuid}/',
                        timeout=TIMEOUT_ALTERNATIVES
                    )
                    
                    if result_response.status_code == 200:
                        data = result_response.json()
                        verdict = data.get('verdicts', {})
                        overall = verdict.get('overall', {})
                        
                        malicious = 1 if overall.get('malicious', False) else 0
                        suspicious = 1 if overall.get('suspicious', False) else 0
                        
                        detections = []
                        if malicious:
                            detections.append({
                                'engine': 'URLScan.io',
                                'method': 'Automated Scan',
                                'result': 'Malicious'
                            })
                        elif suspicious:
                            detections.append({
                                'engine': 'URLScan.io',
                                'method': 'Automated Scan',
                                'result': 'Suspicious'
                            })
                        
                        return {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": 1 if not malicious and not suspicious else 0,
                            "total": 1,
                            "detections": detections,
                            "source": "URLScan.io"
                        }
                    elif result_response.status_code == 404:
                        # Escaneo aún no completado, continuar esperando
                        continue
                    else:
                        break
        
        # Si falla el escaneo, intentar buscar resultados existentes
        # La búsqueda también consume cuota, verificar antes de hacerla
        can_search, _ = URLSCAN_QUOTA.can_query()
        if can_search:
            domain = tldextract.extract(url).domain
            search_response = requests.get(
                f'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                headers={k: v for k, v in headers.items() if v is not None},
                timeout=TIMEOUT_ALTERNATIVES
            )
            
            if search_response.status_code == 200:
                # Registrar cuota solo cuando la búsqueda es exitosa
                URLSCAN_QUOTA.record_query()
                
                search_data = search_response.json()
                results = search_data.get('results', [])
                if results:
                    # Tomar el resultado más reciente
                    latest = results[0]
                    verdict = latest.get('verdicts', {})
                    overall = verdict.get('overall', {})
                    
                    malicious = 1 if overall.get('malicious', False) else 0
                    suspicious = 1 if overall.get('suspicious', False) else 0
                    
                    return {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": 1 if not malicious and not suspicious else 0,
                        "total": 1,
                        "detections": [{'engine': 'URLScan.io', 'result': 'Malicious'}] if malicious else [],
                        "source": "URLScan.io (cached)"
                    }
        
        return None
    except Exception as e:
        logger.debug(f"Error consultando URLScan.io: {str(e)}")
        return None


def check_google_safe_browsing(url):
    """
    Consulta Google Safe Browsing API para una URL.
    Google Safe Browsing es gratuito con límites: 10,000 consultas/día.
    """
    if 'googlesb' not in ENABLED_ALTERNATIVES or not GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    
    # Verificar cuota antes de consultar
    can_query, limit_type = GOOGLE_SB_QUOTA.can_query()
    if not can_query:
        remaining = GOOGLE_SB_QUOTA.get_remaining()
        logger.debug(f"Google Safe Browsing: Cuota {limit_type} agotada. Restantes: {remaining}")
        return None
    
    try:
        # Google Safe Browsing API v4
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
        
        payload = {
            'client': {
                'clientId': 'threatanalyzer',
                'clientVersion': '1.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=TIMEOUT_ALTERNATIVES)

        if response.status_code == 200:
            data = response.json()
            # Si la respuesta está vacía o no tiene 'matches', significa que no hay amenazas
            if not data or data == {}:
                GOOGLE_SB_QUOTA.record_query()
                return {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 1,
                    "total": 1,
                    "detections": [],
                    "source": "Google Safe Browsing"
                }
            
            matches = data.get('matches', [])
            
            # Si hay matches, la URL está en la lista de amenazas
            if matches and len(matches) > 0:
                threat_types = [m.get('threatType', 'UNKNOWN') for m in matches]
                malicious = 1 if any('MALWARE' in t or 'SOCIAL_ENGINEERING' in t for t in threat_types) else 0
                suspicious = 1 if any('UNWANTED_SOFTWARE' in t or 'POTENTIALLY_HARMFUL' in t for t in threat_types) else 0
                
                # Si hay matches pero no se clasificó como malicious/suspicious, marcarlo como suspicious por defecto
                if not malicious and not suspicious:
                    suspicious = 1
                
                detections = []
                for match in matches:
                    detections.append({
                        'engine': 'Google Safe Browsing',
                        'method': match.get('threatType', 'Unknown'),
                        'result': match.get('threatType', 'Threat Detected')
                    })
                
                # Registrar consulta exitosa
                GOOGLE_SB_QUOTA.record_query()
                
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 0,
                    "total": len(matches),
                    "detections": detections,
                    "source": "Google Safe Browsing"
                }
            else:
                # No hay matches, la URL está limpia
                GOOGLE_SB_QUOTA.record_query()
                
                return {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 1,
                    "total": 1,
                    "detections": [],
                    "source": "Google Safe Browsing"
                }
        elif response.status_code == 400:
            # Error en la petición, pero no consumir cuota
            logger.warning(f"Google Safe Browsing: Error 400 - {response.text[:200]}")
            return None
        
        return None
    except Exception as e:
        logger.debug(f"Error consultando Google Safe Browsing: {str(e)}")
        return None


def check_phishtank(url):
    """
    Consulta PhishTank para verificar si una URL es phishing.
    PhishTank es gratuito y no requiere API key (pero se puede usar una opcional).
    Límites conservadores: 10/min, 100/hora, 1000/día.
    """
    if 'phishtank' not in ENABLED_ALTERNATIVES:
        return None
    
    # Verificar cuota antes de consultar
    can_query, limit_type = PHISHTANK_QUOTA.can_query()
    if not can_query:
        remaining = PHISHTANK_QUOTA.get_remaining()
        logger.debug(f"PhishTank: Cuota {limit_type} agotada. Restantes: {remaining}")
        return None
    
    try:
        # PhishTank API
        api_url = 'http://checkurl.phishtank.com/checkurl/'
        
        payload = {
            'url': url,
            'format': 'json',
            'app_key': PHISHTANK_API_KEY if PHISHTANK_API_KEY else None
        }
        
        # Filtrar None values
        payload = {k: v for k, v in payload.items() if v is not None}
        
        response = requests.post(api_url, data=payload, timeout=TIMEOUT_ALTERNATIVES)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', {})
            in_database = results.get('in_database', False)
            phish_id = results.get('phish_id')
            
            # Registrar consulta exitosa
            PHISHTANK_QUOTA.record_query()
            
            if in_database and phish_id:
                return {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 0,
                    "total": 1,
                    "detections": [{
                        'engine': 'PhishTank',
                        'method': 'Phishing Database',
                        'result': f'Phishing (ID: {phish_id})'
                    }],
                    "source": "PhishTank"
                }
            else:
                return {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 1,
                    "total": 1,
                    "detections": [],
                    "source": "PhishTank"
                }
        
        return None
    except Exception as e:
        logger.debug(f"Error consultando PhishTank: {str(e)}")
        return None


def check_abuseipdb(url):
    """
    Consulta AbuseIPDB para verificar la reputación del dominio/IP.
    AbuseIPDB tiene un plan gratuito: 1,000 consultas/día (endpoint check).
    Usa caché por dominio para evitar consultas duplicadas cuando múltiples URLs comparten el mismo dominio.
    """
    if 'abuseipdb' not in ENABLED_ALTERNATIVES or not ABUSEIPDB_API_KEY:
        return None
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Normalizar dominio: eliminar puerto si existe
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Verificar caché primero (por dominio, no por URL)
        # Esto evita consultar el mismo dominio múltiples veces
        if domain in ABUSEIPDB_CACHE:
            logger.info(f"AbuseIPDB: Resultado desde caché para el dominio {domain} (URL: {url[:50]}...)")
            # Mover al final (LRU)
            ABUSEIPDB_CACHE.move_to_end(domain)
            return ABUSEIPDB_CACHE[domain]
        
        # Verificar cuota antes de consultar
        can_query, limit_type = ABUSEIPDB_QUOTA.can_query()
        if not can_query:
            remaining = ABUSEIPDB_QUOTA.get_remaining()
            logger.warning(f"AbuseIPDB: Cuota {limit_type} agotada. Restantes: {remaining}. No se puede consultar dominio {domain}")
            return None
        
        logger.info(f"AbuseIPDB: Consultando dominio {domain} (URL: {url[:50]}...)")
        
        # Resolver dominio a IP (AbuseIPDB solo acepta IPs, no dominios)
        try:
            import socket
            ip = socket.gethostbyname(domain)
            logger.info(f"AbuseIPDB: Dominio {domain} resuelto a IP {ip}")
        except socket.gaierror:
            logger.warning(f"AbuseIPDB: No se pudo resolver el dominio {domain} a IP (URL: {url[:50]}...)")
            return None
        except Exception as e:
            logger.warning(f"AbuseIPDB: Error resolviendo dominio {domain}: {str(e)} (URL: {url[:50]}...)")
            return None
        
        # AbuseIPDB API
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        # Consultar por IP (AbuseIPDB solo acepta IPs)
        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params={
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            },
            timeout=TIMEOUT_ALTERNATIVES
        )

        if response.status_code == 200:
            logger.info(f"AbuseIPDB: Respuesta exitosa para dominio {domain} (IP: {ip})")
            data = response.json()
            data_info = data.get('data', {})
            
            abuse_confidence = data_info.get('abuseConfidenceScore', 0)
            total_reports = data_info.get('totalReports', 0)
            usage_type = (data_info.get('usageType') or '').lower()
            is_tor = data_info.get('isTor', False)
            is_hosting = 'hosting' in usage_type or 'data center' in usage_type
            
            # Considerar tanto el confidence score como el número de reportes
            # Si hay reportes pero el confidence es bajo, aún es sospechoso
            has_reports = total_reports > 0
            
            # Clasificación mejorada:
            # - Malicious: confidence >= 75 O (confidence >= 50 Y reportes >= 3)
            # - Suspicious: confidence >= 25 O (confidence > 0 Y reportes >= 1) O (reportes >= 2)
            malicious = 1 if (abuse_confidence >= 75) or (abuse_confidence >= 50 and total_reports >= 3) else 0
            suspicious = 1 if (abuse_confidence >= 25) or (total_reports >= 3) or (total_reports >= 1 and is_tor) or (total_reports >= 1 and not is_hosting) else 0
            
            detections = []
            if malicious or suspicious:
                detection_info = f'Abuse Confidence: {abuse_confidence}%'
                if total_reports > 0:
                    detection_info += f', Reports: {total_reports}'
                detections.append({
                    'engine': 'AbuseIPDB',
                    'method': 'IP Reputation',
                    'result': detection_info
                })
            
            # Registrar consulta exitosa
            ABUSEIPDB_QUOTA.record_query()
            
            result = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": 1 if (abuse_confidence < 25 and total_reports == 0) else 0,
                "total": 1,
                "detections": detections,
                "source": "AbuseIPDB",
                "abuse_confidence": abuse_confidence,
                "total_reports": total_reports
            }
            
            # Guardar en caché por dominio (no por URL ni IP)
            # Esto permite reutilizar resultados para todas las URLs del mismo dominio
            if len(ABUSEIPDB_CACHE) >= MAX_ABUSEIPDB_CACHE_SIZE:
                # Eliminar el más antiguo (FIFO)
                ABUSEIPDB_CACHE.popitem(last=False)
            ABUSEIPDB_CACHE[domain] = result
            ABUSEIPDB_CACHE.move_to_end(domain)  # Mover al final (LRU)
            
            logger.info(f"AbuseIPDB: Resultado para dominio {domain} (IP: {ip}) guardado en caché. Malicious: {malicious}, Suspicious: {suspicious}, Reports: {total_reports}")
            
            return result
        elif response.status_code == 429:
            logger.warning(f"AbuseIPDB: Rate limit alcanzado para dominio {domain}")
            return None
        else:
            logger.warning(f"AbuseIPDB: Error {response.status_code} para dominio {domain} (IP: {ip}): {response.text[:200]}")
            return None
    except Exception as e:
        logger.error(f"Error consultando AbuseIPDB para dominio {domain}: {str(e)}", exc_info=True)
        return None


def check_url_reputation(url, skip_rate_limit=False):
    """
    Consulta VirusTotal primero, y si no está disponible o falla, usa alternativas gratuitas.
    Combina resultados de múltiples fuentes cuando es posible.
    """
    # Intentar VirusTotal primero
    #vt_result = check_virustotal(url, skip_rate_limit=skip_rate_limit)
    vt_result = None
    
    # Si VirusTotal funciona y tiene resultados, usarlo
    if vt_result and not vt_result.get('error') and not vt_result.get('status') == 'Rate Limited':
        if vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0:
            return vt_result
        # Si VirusTotal dice que está limpio pero queremos confirmación, usar alternativas
        if vt_result.get('total', 0) > 0:
            return vt_result
    
    # Si VirusTotal no está disponible o falló, usar alternativas
    alternative_results = []
    
    # URLScan.io
    urlscan_result = check_urlscan(url)
    if urlscan_result:
        alternative_results.append(urlscan_result)
    
    # Google Safe Browsing
    gsb_result = check_google_safe_browsing(url)
    if gsb_result:
        alternative_results.append(gsb_result)
    
    # PhishTank
    phishtank_result = check_phishtank(url)
    if phishtank_result:
        alternative_results.append(phishtank_result)
    
    # AbuseIPDB
    abuseipdb_result = check_abuseipdb(url)
    if abuseipdb_result:
        alternative_results.append(abuseipdb_result)
    
    # Combinar resultados de servicios
    if alternative_results:
        combined_malicious = sum(r.get('malicious', 0) for r in alternative_results)
        combined_suspicious = sum(r.get('suspicious', 0) for r in alternative_results)
        combined_harmless = sum(r.get('harmless', 0) for r in alternative_results)
        combined_total = len(alternative_results)
        
        # Combinar detecciones
        all_detections = []
        for result in alternative_results:
            all_detections.extend(result.get('detections', []))
        
        sources = [r.get('source', 'Unknown') for r in alternative_results]
        
        return {
            "malicious": combined_malicious,
            "suspicious": combined_suspicious,
            "harmless": combined_harmless,
            "total": combined_total,
            "detections": all_detections[:20],  # Limitar a 20
            "sources": sources,
            "fallback": True,  # Indicar que se usaron alternativas
            "vt_status": vt_result.get('status') if vt_result else 'Not Available'
        }
    
    # Si no hay alternativas disponibles, devolver el resultado de VirusTotal (aunque sea error)
    if vt_result:
        return vt_result
    
    # Último recurso: devolver resultado vacío
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total": 0,
        "detections": [],
        "status": "No services available",
        "message": "VirusTotal no disponible y alternativas no configuradas"
    }


SHORTENERS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 'rebrand.ly',
    'mandrillapp.com', 'sendgrid.net', 'constantcontact.com', 'mcsv.net', 'url12.net'
]

def unshorten_url(url, max_redirects=10):
    """
    Desacorta una URL y rastrea todas las redirecciones.
    Devuelve la URL final después de todas las redirecciones.
    """
    if not url or not isinstance(url, str):
        return url
    
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Intentar desacortar si es un acortador conocido o contiene palabras clave
        should_unshorten = (domain in SHORTENERS or 
                          "track" in url.lower() or 
                          "click" in url.lower() or
                          "redirect" in url.lower() or
                          "link" in url.lower())
        
        if should_unshorten:
            logger.info(f"Desacortando URL: {url[:50]}...")
            try:
                # Usar HEAD primero (más rápido), pero algunos servidores no lo soportan
                # requests maneja automáticamente las redirecciones con allow_redirects=True
                session = requests.Session()
                session.max_redirects = max_redirects
                response = session.head(url, headers=HEADERS, allow_redirects=True, 
                                       timeout=TIMEOUT_HTTP)
                final_url = response.url
            except requests.exceptions.TooManyRedirects:
                logger.warning(f"Demasiadas redirecciones para {url[:50]}")
                return url
            except Exception:
                # Si HEAD falla, intentar con GET (más lento pero más compatible)
                try:
                    session = requests.Session()
                    session.max_redirects = max_redirects
                    response = session.get(url, headers=HEADERS, allow_redirects=True, 
                                           timeout=TIMEOUT_HTTP, stream=True)
                    final_url = response.url
                    response.close()  # Cerrar la conexión sin descargar el cuerpo
                except requests.exceptions.TooManyRedirects:
                    logger.warning(f"Demasiadas redirecciones para {url[:50]}")
                    return url
                except Exception as e:
                    logger.warning(f"Error desacortando URL {url[:50]}: {str(e)}")
                    return url
            
            if final_url != url:
                logger.info(f"URL desacortada: {url[:50]}... -> {final_url[:50]}...")
            return final_url
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout desacortando URL: {url[:50]}")
    except Exception as e:
        logger.warning(f"Error desacortando URL {url[:50]}: {str(e)}")
    
    return url

def sanitize_html(content):
    """
    Sanitiza el contenido HTML eliminando scripts, estilos peligrosos y otros elementos maliciosos.
    Mantiene solo etiquetas y atributos seguros para análisis.
    """
    if not content or not isinstance(content, str):
        return ""
    
    # Primero, sanitizar con bleach para eliminar contenido peligroso
    sanitized = bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True  # Eliminar etiquetas no permitidas en lugar de escapar
    )
    
    # Eliminar scripts inline y estilos peligrosos que puedan quedar
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'<style[^>]*>.*?</style>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)  # Eliminar event handlers
    
    return sanitized

def analyze_with_google_ai(content_type, content, context=None):
    """
    Analiza contenido (URL, email o SMS) usando Google AI Studio (Gemma 3).
    Retorna un diccionario con la opinión de la IA.
    
    content_type: 'url', 'email', o 'sms'
    content: El contenido a analizar
    context: Contexto adicional (opcional, para emails/SMS puede incluir URLs detectadas)
    """
    if not GOOGLE_AI_API_KEY:
        logger.debug("Google AI API key no configurada, omitiendo análisis de IA")
        return {
            "enabled": False,
            "risk_score": 0,
            "analysis": "Análisis de IA no disponible (API key no configurada)",
            "reasoning": "",
            "confidence": 0
        }
    
    try:
        logger.info(f"Iniciando análisis de IA para {content_type}...")
        # Construir el prompt según el tipo de contenido
        if content_type == 'url':
            prompt = f"""Analiza la siguiente URL y determina si es potencialmente maliciosa o sospechosa.

URL: {content}

Considera:
- Si el dominio es sospechoso o desconocido
- Si la URL parece ser un acortador o redirección
- Si hay indicios de phishing, malware o estafa
- La estructura y apariencia general de la URL

Responde en formato JSON con:
- "risk_level": "bajo", "medio" o "alto"
- "risk_score": número del 0 al 100
- "analysis": breve análisis de la URL
- "reasoning": razonamiento detallado
- "confidence": nivel de confianza del 0 al 100

Solo responde con el JSON, sin texto adicional."""
        
        elif content_type == 'email':
            context_info = ""
            if context and isinstance(context, dict):
                urls_info = context.get('urls', [])
                if urls_info:
                    urls_text = "\n".join([f"- {u.get('url', u)}" for u in urls_info[:10]])
                    context_info = f"\n\nURLs detectadas en el email:\n{urls_text}"
            
            prompt = f"""Analiza el siguiente email y determina si es potencialmente malicioso o sospechoso (phishing, spam, estafa).

Contenido del email:
{content[:3000]}{context_info}

Considera:
- Contenido sospechoso o urgente
- Faltas de ortografía excesivas
- Solicitudes de información personal o credenciales
- Amenazas o presión para actuar rápidamente
- URLs sospechosas en el contenido
- Remitente desconocido o sospechoso

Responde en formato JSON con:
- "risk_level": "bajo", "medio" o "alto"
- "risk_score": número del 0 al 100
- "analysis": breve análisis del email
- "reasoning": razonamiento detallado
- "confidence": nivel de confianza del 0 al 100

Solo responde con el JSON, sin texto adicional."""
        
        elif content_type == 'sms':
            context_info = ""
            if context and isinstance(context, dict):
                urls_info = context.get('urls', [])
                if urls_info:
                    urls_text = "\n".join([f"- {u.get('url', u)}" for u in urls_info[:10]])
                    context_info = f"\n\nURLs detectadas en el SMS:\n{urls_text}"
            
            prompt = f"""Analiza el siguiente SMS y determina si es potencialmente malicioso o sospechoso (smishing, estafa).

Contenido del SMS:
{content[:2000]}{context_info}

Considera:
- Contenido sospechoso o urgente
- Solicitudes de información personal o credenciales
- Amenazas o presión para actuar rápidamente
- URLs sospechosas en el contenido
- Remitente desconocido o sospechoso
- Indicadores de smishing (phishing por SMS)

Responde en formato JSON con:
- "risk_level": "bajo", "medio" o "alto"
- "risk_score": número del 0 al 100
- "analysis": breve análisis del SMS
- "reasoning": razonamiento detallado
- "confidence": nivel de confianza del 0 al 100

Solo responde con el JSON, sin texto adicional."""
        else:
            return {
                "enabled": False,
                "risk_score": 0,
                "analysis": "Tipo de contenido no soportado",
                "reasoning": "",
                "confidence": 0
            }
        
        # Llamar a la API de Google AI Studio
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GOOGLE_AI_MODEL}:generateContent?key={GOOGLE_AI_API_KEY}"
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.3,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 1024,
            }
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        logger.debug(f"Consultando Google AI Studio para análisis de {content_type}...")
        response = requests.post(url, json=payload, headers=headers, timeout=GOOGLE_AI_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            # Extraer el texto de la respuesta
            if 'candidates' in data and len(data['candidates']) > 0:
                text_response = data['candidates'][0]['content']['parts'][0]['text']
                
                # Intentar parsear JSON de la respuesta
                try:
                    # Limpiar la respuesta (puede tener markdown o texto adicional)
                    text_response = text_response.strip()
                    # Eliminar markdown code blocks si existen
                    if text_response.startswith('```'):
                        lines = text_response.split('\n')
                        text_response = '\n'.join(lines[1:-1]) if len(lines) > 2 else text_response
                    if text_response.startswith('```json'):
                        lines = text_response.split('\n')
                        text_response = '\n'.join(lines[1:-1]) if len(lines) > 2 else text_response
                    
                    ai_result = json.loads(text_response)
                    
                    # Normalizar los valores
                    risk_score = int(ai_result.get('risk_score', 0))
                    risk_level = ai_result.get('risk_level', 'bajo').lower()
                    
                    # Convertir risk_level a score si no viene el score
                    if risk_score == 0 and risk_level:
                        if risk_level == 'alto':
                            risk_score = 80
                        elif risk_level == 'medio':
                            risk_score = 50
                        else:
                            risk_score = 20
                    
                    return {
                        "enabled": True,
                        "risk_score": min(100, max(0, risk_score)),
                        "risk_level": risk_level,
                        "analysis": ai_result.get('analysis', ''),
                        "reasoning": ai_result.get('reasoning', ''),
                        "confidence": min(100, max(0, int(ai_result.get('confidence', 50))))
                    }
                except json.JSONDecodeError:
                    # Si no se puede parsear JSON, intentar extraer información del texto
                    logger.warning(f"Respuesta de IA no es JSON válido, parseando texto: {text_response[:200]}")
                    # Buscar números que puedan ser risk_score
                    import re
                    score_match = re.search(r'risk[_\s]*score["\']?\s*[:=]\s*(\d+)', text_response, re.IGNORECASE)
                    risk_score = int(score_match.group(1)) if score_match else 50
                    
                    return {
                        "enabled": True,
                        "risk_score": min(100, max(0, risk_score)),
                        "risk_level": "medio",
                        "analysis": text_response[:500],
                        "reasoning": text_response,
                        "confidence": 60
                    }
            else:
                logger.warning(f"Respuesta de Google AI sin candidatos: {data}")
                return {
                    "enabled": True,
                    "risk_score": 0,
                    "analysis": "No se pudo obtener análisis de la IA",
                    "reasoning": "",
                    "confidence": 0
                }
        else:
            logger.error(f"Error consultando Google AI Studio: {response.status_code} - {response.text[:200]}")
            return {
                "enabled": False,
                "risk_score": 0,
                "analysis": f"Error al consultar IA: {response.status_code}",
                "reasoning": "",
                "confidence": 0
            }
    except requests.exceptions.Timeout:
        logger.error(f"Timeout consultando Google AI Studio para {content_type}")
        return {
            "enabled": False,
            "risk_score": 0,
            "analysis": "Timeout al consultar IA",
            "reasoning": "",
            "confidence": 0
        }
    except Exception as e:
        logger.error(f"Error consultando Google AI Studio: {str(e)}", exc_info=True)
        return {
            "enabled": False,
            "risk_score": 0,
            "analysis": f"Error: {str(e)}",
            "reasoning": "",
            "confidence": 0
        }

def normalize_url(url):
    """
    Normaliza una URL eliminando parámetros de tracking comunes y fragmentos.
    Esto ayuda a identificar URLs duplicadas que solo difieren en parámetros.
    """
    if not url or not isinstance(url, str):
        return url
    
    try:
        # Parsear URL
        parsed = urlparse(url)
        
        # Eliminar fragmento (#)
        parsed = parsed._replace(fragment='')
        
        # Normalizar parámetros de query - eliminar parámetros de tracking comunes
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            # Lista de parámetros de tracking comunes a eliminar
            tracking_params = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                              'ref', 'source', 'campaign', 'medium', 'fbclid', 'gclid', '_ga', '_gl']
            
            # Eliminar parámetros de tracking
            filtered_params = {k: v for k, v in query_params.items() 
                             if k.lower() not in [p.lower() for p in tracking_params]}
            
            if filtered_params:
                # Reconstruir query string
                new_query = urlencode(filtered_params, doseq=True)
                parsed = parsed._replace(query=new_query)
            else:
                parsed = parsed._replace(query='')
        
        # Reconstruir URL normalizada
        normalized = urlunparse(parsed)
        return normalized
    except Exception as e:
        logger.debug(f"Error normalizando URL {url[:50]}: {str(e)}")
        return url

def extract_urls(content):
    """
    Extrae todas las URLs del contenido, tanto del HTML como del texto plano.
    No normaliza las URLs para preservar la información original.
    """
    urls = set()
    
    # 1. Buscar URLs en el contenido original con regex mejorado
    # Patrón más exhaustivo que captura URLs incluso con caracteres especiales
    url_patterns = [
        r'https?://[^\s<>"\'\)\[\]{}|`]+',  # URLs completas
        r'www\.[^\s<>"\'\)\[\]{}|`]+',      # URLs que empiezan con www.
        r'[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}/[^\s<>"\'\)\[\]{}|`]*',  # URLs sin protocolo
    ]
    
    for pattern in url_patterns:
        regex_urls = re.findall(pattern, content, re.IGNORECASE)
        for u in regex_urls:
            # Limpiar y normalizar
            u = u.strip().rstrip('.,;:!?)')
            if u.startswith('www.'):
                u = 'https://' + u
            elif not u.startswith(('http://', 'https://')):
                # Si parece una URL pero no tiene protocolo, agregar https://
                if '.' in u and '/' in u:
                    u = 'https://' + u
                else:
                    continue
            if u.startswith(('http://', 'https://')):
                urls.add(u)
    
    # 2. Buscar URLs en etiquetas HTML (usar contenido original)
    try:
        soup = BeautifulSoup(content, 'html.parser')
        
        # Buscar en href de enlaces
        for a in soup.find_all(['a', 'area', 'link'], href=True):
            href = a.get('href', '').strip()
            if href:
                # Resolver URLs relativas y protocolo-relative
                if href.startswith('//'):
                    href = 'https:' + href
                elif href.startswith('/'):
                    # URL relativa, intentar construir completa si hay base
                    base_tag = soup.find('base', href=True)
                    if base_tag:
                        base = base_tag.get('href', '').strip()
                        if base:
                            href = urljoin(base, href)
                    # Si no hay base, mantener la relativa (se puede analizar después)
                if href.startswith(('http://', 'https://')):
                    urls.add(href)
        
        # Buscar en src de imágenes y otros elementos
        for tag in soup.find_all(['img', 'iframe', 'embed', 'source', 'video', 'audio'], src=True):
            src = tag.get('src', '').strip()
            if src:
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    base_tag = soup.find('base', href=True)
                    if base_tag:
                        base = base_tag.get('href', '').strip()
                        if base:
                            src = urljoin(base, src)
                if src.startswith(('http://', 'https://')):
                    urls.add(src)
        
        # Buscar en otros atributos que pueden contener URLs
        url_attributes = ['data-url', 'data-link', 'data-href', 'action', 'formaction', 
                         'cite', 'background', 'poster', 'srcset']
        for tag in soup.find_all(True):
            for attr in url_attributes:
                if tag.has_attr(attr):
                    url_value = tag.get(attr, '').strip()
                    if url_value:
                        # srcset puede tener múltiples URLs
                        if attr == 'srcset':
                            # Parsear srcset: "url1 1x, url2 2x"
                            srcset_urls = re.findall(r'(https?://[^\s,]+)', url_value)
                            for su in srcset_urls:
                                urls.add(su)
                        elif url_value.startswith(('http://', 'https://')):
                            urls.add(url_value)
                        elif url_value.startswith('//'):
                            urls.add('https:' + url_value)
        
        # Buscar URLs en estilos inline (background-image: url(...))
        for tag in soup.find_all(True):
            style = tag.get('style', '')
            if style:
                style_urls = re.findall(r'url\(["\']?(https?://[^"\')\s]+)', style, re.IGNORECASE)
                for su in style_urls:
                    urls.add(su)
    except Exception as e:
        logger.warning(f"Error extrayendo URLs del HTML: {str(e)}")
    
    # 3. Filtrar URLs y eliminar duplicados (pero NO filtrar por dominios confiables aquí)
    filtered_urls = []
    seen_urls = set()  # Para evitar duplicados exactos
    
    for u in urls:
        if u.startswith('mailto:') or u.startswith('tel:') or u.startswith('javascript:'):
            continue
        
        # Limpiar URL de caracteres finales problemáticos
        u = u.rstrip('.,;:!?)')
        
        # Normalizar para comparación (pero mantener original)
        normalized = normalize_url(u)
        if normalized not in seen_urls and len(normalized) > 10:  # Filtrar URLs muy cortas
            filtered_urls.append(u)  # Guardar URL original
            seen_urls.add(normalized)
    
    logger.debug(f"URLs extraídas: {len(urls)}, URLs únicas después de filtrado: {len(filtered_urls)}")
    return filtered_urls

def expand_urls(urls):
    """
    Expande URLs acortadas y rastrea redirecciones.
    Devuelve un diccionario con URLs originales y sus versiones expandidas.
    """
    expanded = {}
    all_urls = set()
    
    for url in urls:
        if not url or not isinstance(url, str):
            continue
        
        original_url = url
        all_urls.add(original_url)
        
        try:
            # Intentar desacortar
            unshortened = unshorten_url(url)
            if unshortened and unshortened != original_url:
                expanded[original_url] = unshortened
                all_urls.add(unshortened)
                logger.info(f"URL expandida: {original_url[:50]}... -> {unshortened[:50]}...")
        except Exception as e:
            logger.debug(f"Error expandiendo URL {url[:50]}: {str(e)}")
            # Si falla, mantener la URL original
            if original_url not in expanded:
                expanded[original_url] = original_url
    
    # Agregar URLs que no se expandieron
    for url in urls:
        if url not in expanded:
            expanded[url] = url
    
    return list(all_urls), expanded

def get_cache_key_url(url):
    """Genera una clave única para una URL normalizada"""
    normalized = normalize_url(url)
    if not normalized.startswith(('http://', 'https://')):
        normalized = 'https://' + normalized
    # Usar hash SHA256 para la clave
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

def get_cache_key_email(content):
    """Genera una clave única para el contenido de un email"""
    # Sanitizar y normalizar el contenido antes de hashear
    sanitized = sanitize_html(content)
    # Eliminar espacios en blanco extra y normalizar
    normalized = re.sub(r'\s+', ' ', sanitized.strip())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

def get_cache_key_sms(sender, content):
    """Genera una clave única para un SMS"""
    # Combinar remitente y contenido normalizado
    sender_clean = re.sub(r'\D', '', sender) if sender else ''
    content_normalized = re.sub(r'\s+', ' ', content.strip())
    combined = f"{sender_clean}|{content_normalized}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def init_cache_db():
    """Inicializa la base de datos SQLite para la caché"""
    conn = sqlite3.connect(CACHE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_cache (
            cache_key TEXT PRIMARY KEY,
            result_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_updated_at ON analysis_cache(updated_at)
    ''')
    conn.commit()
    conn.close()
    logger.info(f"Base de datos de caché inicializada: {CACHE_DB_PATH}")

def get_from_cache(cache_key):
    """Obtiene un resultado del caché si existe y está habilitado"""
    global CACHE_ENABLED
    
    # Si la caché está deshabilitada, no consultar
    if not CACHE_ENABLED:
        return None
    
    try:
        conn = sqlite3.connect(CACHE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT result_data, updated_at FROM analysis_cache WHERE cache_key = ?', (cache_key,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            result_data = json.loads(row[0])
            logger.info(f"Cache hit para análisis: {cache_key[:16]}...")
            return result_data
    except Exception as e:
        logger.error(f"Error al leer de caché SQLite: {str(e)}")
    
    return None

def save_to_cache(cache_key, result):
    """Guarda un resultado en el caché SQLite.
    Si la caché está desactivada, solo guarda resultados nuevos o más actuales.
    Si la caché está activada, siempre guarda."""
    global CACHE_ENABLED
    
    try:
        conn = sqlite3.connect(CACHE_DB_PATH)
        cursor = conn.cursor()
        
        # Verificar si ya existe
        cursor.execute('SELECT updated_at FROM analysis_cache WHERE cache_key = ?', (cache_key,))
        existing = cursor.fetchone()
        
        result_json = json.dumps(result)
        
        # Si la caché está desactivada, solo guardar si es un resultado nuevo
        # Si está activada, siempre guardar/actualizar
        if not CACHE_ENABLED and existing:
            # Caché desactivada y ya existe: no actualizar
            conn.close()
            return
        
        if existing:
            # Actualizar resultado existente
            cursor.execute('''
                UPDATE analysis_cache 
                SET result_data = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE cache_key = ?
            ''', (result_json, cache_key))
            logger.debug(f"Resultado actualizado en caché: {cache_key[:16]}...")
        else:
            # Insertar nuevo resultado
            cursor.execute('''
                INSERT INTO analysis_cache (cache_key, result_data, created_at, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (cache_key, result_json))
            logger.debug(f"Resultado guardado en caché: {cache_key[:16]}...")
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error al guardar en caché SQLite: {str(e)}")

def calculate_url_priority(url, ssl_info, whois_info, is_shortened):
    """
    Calcula la prioridad de una URL para análisis de reputación.
    Retorna un score de prioridad (mayor = más prioritario).
    """
    priority = 0
    
    # SSL inválido o expirado = alta prioridad
    if ssl_info.get('status') != 'Secure':
        priority += 50
    elif ssl_info.get('remaining_days', 999) < 30:
        priority += 20
    
    # Dominio reciente = alta prioridad
    if whois_info.get('is_recent'):
        priority += 60
    
    # URL acortada = prioridad media
    if is_shortened:
        priority += 30
    
    # Servicios de hosting = prioridad media-baja
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if any(service in domain.lower() for service in HOSTING_SERVICES):
            priority += 15
    except:
        pass
    
    # Dominios sospechosos por nombre
    suspicious_keywords = ['track', 'click', 'redirect', 'link', 'short', 'bit.ly', 'tinyurl']
    if any(kw in url.lower() for kw in suspicious_keywords):
        priority += 25
    
    return priority

def analyze_single_url(url, skip_vt_rate_limit=False):
    """
    Analiza una URL individual.
    skip_vt_rate_limit: Si es True, ignora el rate limit de VirusTotal (para URLs prioritarias)
    """
    # Verificar caché primero
    cache_key = get_cache_key_url(url)
    cached_result = get_from_cache(cache_key)
    if cached_result:
        logger.info(f"Devolviendo análisis de URL desde caché: {url[:50]}...")
        return cached_result
    
    original_url = url
    url = unshorten_url(url)
    is_was_shortened = (url != original_url)
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        hostname = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else domain
        # Usar hostname completo para mostrar en la lista si hay subdominio, sino usar dominio base
        display_domain = hostname if extracted.subdomain else domain
        
        # Primero obtener SSL y WHOIS (más rápidos)
        ssl_info = get_ssl_info(hostname)
        whois_info = get_domain_age(domain)
        
        # Calcular prioridad antes de consultar servicios de reputación
        priority = calculate_url_priority(url, ssl_info, whois_info, is_was_shortened)
        
        # Consultar VirusTotal (con fallback a alternativas si no está disponible)
        reputation_info = check_url_reputation(url, skip_rate_limit=skip_vt_rate_limit)
        
        risk_score = 0
        risk_factors = []
        if ssl_info.get('status') != 'Secure':
            risk_score += 30
            risk_factors.append(f"[{display_domain}] SSL Inválido o inexistente")
        if whois_info.get('is_recent'):
            risk_score += 40
            risk_factors.append(f"[{display_domain}] Dominio muy reciente")
        if reputation_info.get('malicious', 0) > 0:
            risk_score += 60
            sources = reputation_info.get('sources', ['Servicios de análisis'])
            risk_factors.append(f"[{display_domain}] {', '.join(sources)}: {reputation_info['malicious']} detección(es) maliciosa(s)")
        if any(service in domain.lower() or service in hostname.lower() for service in HOSTING_SERVICES):
            risk_score += 25
            risk_factors.append(f"[{display_domain}] Enlace a servicio de alojamiento público")
        if is_was_shortened:
            risk_factors.append(f"URL acortada detectada. Destino: {url}")
        
        # Análisis paralelo con Google AI (no bloquea el análisis principal)
        ai_analysis = analyze_with_google_ai('url', url)
        
        # Incorporar el riesgo del análisis de IA en el cálculo del riesgo total
        if ai_analysis and ai_analysis.get('enabled') and ai_analysis.get('risk_score', 0) > 0:
            ai_risk_score = ai_analysis.get('risk_score', 0)
            # Usar el máximo entre el riesgo calculado y el riesgo de la IA
            risk_score = max(risk_score, ai_risk_score)
            # Añadir factor de riesgo de IA si es significativo
            if ai_risk_score >= 30:
                ai_level = ai_analysis.get('risk_level', 'medio')
                ai_confidence = ai_analysis.get('confidence', 0)
                risk_factors.append(f"Análisis de IA: {ai_risk_score}% de riesgo ({ai_level}) - Confianza: {ai_confidence}%")
        
        result = {
            "url": url, "original_url": original_url, "domain": display_domain, "base_domain": domain,
            "hostname": hostname, "ssl": ssl_info, "whois": whois_info, "virustotal": reputation_info,
            "risk_score": min(risk_score, 100), "risk_factors": risk_factors, "is_redirected": is_was_shortened,
            "priority": priority,  # Incluir prioridad en el resultado para debugging
            "ai_analysis": ai_analysis  # Análisis de IA en paralelo
        }
        # Guardar en caché
        save_to_cache(cache_key, result)
        return result
    except Exception as e:
        return {
            "url": url, "original_url": original_url, "domain": tldextract.extract(url).top_domain_under_public_suffix or url,
            "ssl": {"status": "Error", "issuer": "N/A", "valid_to": "N/A"},
            "whois": {"age_years": 0, "age_months": 0, "is_recent": False},
            "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 0, "message": "Error"},
            "risk_score": 0, "risk_factors": [str(e)], "is_redirected": is_was_shortened
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@limiter.limit(f"{rate_limit_per_minute} per minute")
def analyze():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type debe ser application/json"}), 400
        
        url = request.json.get('url')
        if not url or not isinstance(url, str):
            return jsonify({"error": "URL requerida"}), 400
        
        # Validar longitud máxima
        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": f"URL demasiado larga (máximo {MAX_URL_LENGTH} caracteres)"}), 400
        
        logger.info(f"Análisis de URL solicitado: {url[:50]}...")
        # Para análisis individual, permitir consulta a VT (skip_rate_limit=True para URLs individuales)
        result = analyze_single_url(url, skip_vt_rate_limit=True)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error en /analyze: {str(e)}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/analyze-email', methods=['POST'])
@limiter.limit(f"{rate_limit_per_minute} per minute")
def analyze_email():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type debe ser application/json"}), 400
        
        content = request.json.get('content')
        if not content or not isinstance(content, str):
            return jsonify({"error": "Contenido de email requerido"}), 400
        
        # Validar longitud máxima
        max_email_size = MAX_EMAIL_SIZE_MB * 1024 * 1024
        if len(content) > max_email_size:
            return jsonify({"error": f"Contenido de email demasiado grande (máximo {MAX_EMAIL_SIZE_MB}MB)"}), 400
        
        logger.info(f"Análisis de email solicitado (tamaño: {len(content)} bytes)")
        
        # Verificar caché primero
        cache_key = get_cache_key_email(content)
        cached_result = get_from_cache(cache_key)
        if cached_result:
            logger.info(f"Devolviendo análisis de email desde caché")
            return jsonify(cached_result)
        
        # Extraer URLs del contenido original (antes de sanitizar para no perder URLs)
        urls = extract_urls(content)
        
        # Expandir URLs (desacortar y rastrear redirecciones)
        all_urls_to_analyze, url_expansions = expand_urls(urls)
        
        # Eliminar duplicados normalizados antes de analizar
        unique_urls = []
        seen_normalized = set()
        for u in all_urls_to_analyze:
            normalized = normalize_url(u)
            if normalized not in seen_normalized:
                unique_urls.append(u)
                seen_normalized.add(normalized)
        
        logger.info(f"Analizando {len(unique_urls)} URLs únicas (de {len(urls)} originales, {len(all_urls_to_analyze)} después de expansión)")
        
        # Paso 1: Analizar todas las URLs primero (para calcular prioridades)
        url_preliminary = []
        for u in unique_urls:
            try:
                original_url = u
                unshortened = unshorten_url(u)
                is_shortened = (unshortened != original_url)
                if not unshortened.startswith(('http://', 'https://')):
                    unshortened = 'https://' + unshortened
                
                extracted = tldextract.extract(unshortened)
                domain = f"{extracted.domain}.{extracted.suffix}"
                hostname = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else domain
                
                # Filtrar dominios de confianza para ahorrar recursos
                if is_trusted_domain(domain) or is_trusted_domain(hostname):
                    logger.debug(f"Dominio de confianza ignorado: {domain} (URL: {unshortened[:50]}...)")
                    # Aún así crear una entrada con riesgo 0 para mantener consistencia
                    url_preliminary.append({
                        'url': unshortened,
                        'original_url': original_url,
                        'ssl_info': {'status': 'Legitimate Domain', 'valid': True},
                        'whois_info': {'is_recent': False, 'age_years': 10},
                        'priority': 0,  # Prioridad mínima
                        'is_shortened': is_shortened,
                        'domain': domain,
                        'hostname': hostname,
                        'is_legitimate': True
                    })
                    continue
                
                ssl_info = get_ssl_info(hostname)
                whois_info = get_domain_age(domain)
                priority = calculate_url_priority(unshortened, ssl_info, whois_info, is_shortened)
                
                url_preliminary.append({
                    'url': unshortened,
                    'original_url': original_url,
                    'ssl_info': ssl_info,
                    'whois_info': whois_info,
                    'priority': priority,
                    'is_shortened': is_shortened,
                    'domain': domain,
                    'hostname': hostname
                })
            except Exception as e:
                logger.warning(f"Error en análisis preliminar de {u[:50]}: {str(e)}")
                continue
        
        # Paso 2: Ordenar por prioridad (mayor primero)
        url_preliminary.sort(key=lambda x: x['priority'], reverse=True)
        logger.info(f"URLs ordenadas por prioridad. Top 5: {[u['url'][:30] + '... (prio: ' + str(u['priority']) + ')' for u in url_preliminary[:5]]}")
        
        # Paso 3: Analizar URLs completas con servicios de reputación
        url_results_all = []
        for prelim in url_preliminary:
            try:
                # Saltar análisis costosos para dominios legítimos
                if prelim.get('is_legitimate', False):
                    result = {
                        "url": prelim['url'],
                        "original_url": prelim['original_url'],
                        "domain": prelim.get('hostname', prelim['domain']),
                        "base_domain": prelim['domain'],
                        "hostname": prelim.get('hostname', prelim['domain']),
                        "ssl": prelim['ssl_info'],
                        "whois": prelim['whois_info'],
                        "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "status": "Legitimate Domain", "detections": []},
                        "risk_score": 0,
                        "risk_factors": [],
                        "is_redirected": prelim['is_shortened']
                    }
                    url_results_all.append(result)
                    continue
                
                # Analizar URL con servicios de reputación
                vt_info = check_url_reputation(prelim['url'])
                
                # Calcular risk_score
                risk_score = 0
                risk_factors = []
                display_domain = prelim['hostname'] if prelim.get('hostname') else prelim['domain']
                
                if prelim['ssl_info'].get('status') != 'Secure':
                    risk_score += 30
                    risk_factors.append(f"[{display_domain}] SSL Inválido o inexistente")
                if prelim['whois_info'].get('is_recent'):
                    risk_score += 40
                    risk_factors.append(f"[{display_domain}] Dominio muy reciente")
                if vt_info.get('malicious', 0) > 0:
                    risk_score += 60
                    sources = vt_info.get('sources', ['Servicios de análisis'])
                    risk_factors.append(f"[{display_domain}] {', '.join(sources)}: {vt_info['malicious']} detección(es) maliciosa(s)")
                if any(service in prelim['domain'].lower() or service in prelim.get('hostname', '').lower() for service in HOSTING_SERVICES):
                    risk_score += 25
                    risk_factors.append(f"[{display_domain}] Enlace a servicio de alojamiento público")
                if prelim['is_shortened']:
                    risk_factors.append(f"URL acortada detectada. Destino: {prelim['url']}")
                
                result = {
                    "url": prelim['url'],
                    "original_url": prelim['original_url'],
                    "domain": display_domain,
                    "base_domain": prelim['domain'],
                    "hostname": prelim.get('hostname', prelim['domain']),
                    "ssl": prelim['ssl_info'],
                    "whois": prelim['whois_info'],
                    "virustotal": vt_info,
                    "risk_score": risk_score,
                    "risk_factors": risk_factors,
                    "is_redirected": prelim['is_shortened']
                }
                url_results_all.append(result)
            except Exception as e:
                logger.error(f"Error analizando URL {prelim['url'][:50]}: {str(e)}", exc_info=True)
                continue
        
        # Filtrar URLs con 0% de riesgo (no son relevantes para mostrar)
        url_results = [r for r in url_results_all if r.get('risk_score', 0) > 0]
        logger.info(f"URLs con riesgo > 0%: {len(url_results)} (de {len(unique_urls)} analizadas)")
        
        # Sanitizar HTML para extracción de texto (después de extraer URLs)
        sanitized_content = sanitize_html(content)
        
        # Usar contenido original para extracción de texto (más información)
        # Pero también usar sanitizado como fallback
        try:
            text_content = BeautifulSoup(content, 'html.parser').get_text()
        except:
            text_content = BeautifulSoup(sanitized_content, 'html.parser').get_text()
        # --- FILTRADO DE METADATOS DE EMAIL ---
        # Eliminar líneas que parecen cabeceras de reenvío/email (De:, Para:, Date:, etc.)
        lines = text_content.split('\n')
        filtered_lines = []
        # Lista extendida de keywords de cabecera
        header_keywords = {'de:', 'to:', 'from:', 'subject:', 'date:', 'enviado el:', 'asunto:', 'para:', 'cc:', 'bcc:', 'sent:', 'reply-to:'}
        
        for line in lines:
            clean_l = line.strip().lower()
            # Si la línea empieza con una keyword de cabecera o tiene el formato typical de "Forwarded" o contiene un email entre < >
            if any(clean_l.startswith(kw) for kw in header_keywords): continue
            if '---' in clean_l and ('forward' in clean_l or 'mensaje' in clean_l): continue
            if '<' in clean_l and '@' in clean_l and '>' in clean_l: continue
            
            filtered_lines.append(line)
        
        clean_text = ' '.join(filtered_lines)
        
        # Limpieza agresiva de strings técnicos
        clean_text = re.sub(r'<[^>]+>', ' ', clean_text) # Eliminar todo lo que esté entre < >
        clean_text = re.sub(r'\[[^+\]]+\]', ' ', clean_text) # Eliminar todo lo que esté entre [ ]
        clean_text = re.sub(r'\S+@\S+', ' ', clean_text) # Eliminar emails
        clean_text = re.sub(r'http\S+', ' ', clean_text) # Eliminar URLs que queden en el texto
        
        words = re.findall(r'\b\w+\b', clean_text)
        # Filtramos palabras: más de 3 letras, que no sean puros números y que no tengan guiones bajos (técnicas)
        words = [w for w in words if len(w) > 3 and not w.isdigit() and '_' not in w]
        
        # Optimización: limitar cantidad de palabras para spellchecker (puede ser lento)
        if len(words) > MAX_WORDS_FOR_SPELLCHECK:
            logger.debug(f"Limitando palabras para spellcheck de {len(words)} a {MAX_WORDS_FOR_SPELLCHECK}")
            words = words[:MAX_WORDS_FOR_SPELLCHECK]
        
        # TECH_WORDS: Palabras que NO son faltas aunque no estén en el diccionario
        TECH_WORDS = {
            'instagram', 'gmail', 'outlook', 'microsoft', 'google', 'facebook', 'whatsapp', 'linkedin', 
            'twitter', 'login', 'click', 'track', 'mandrill', 'nube', 'forwarded', 'message', 'asunto',
            'enviado', 'respondió', 'escribió', 'date', 'subject', 'info', 'safe', 'link'
        }
        
        # Optimizar spellcheck: procesar en lotes más pequeños
        misspelled_es = set()
        batch_size = 100
        for i in range(0, len(words), batch_size):
            batch = words[i:i+batch_size]
            misspelled_es.update(spell_es.unknown(batch))
        
        misspelled_en_set = set()
        for i in range(0, len(words), batch_size):
            batch = words[i:i+batch_size]
            misspelled_en_set.update(spell_en.unknown(batch))
        
        misspelled = [w for w in misspelled_es if w in misspelled_en_set and w.lower() not in TECH_WORDS]
        # --- CÁLCULO DE RIESGO EMAIL ---
        email_risk_score = 0
        email_factors = []
        
        if len(misspelled) > 5:
            email_risk_score += 20
            email_factors.append(f"Faltas de ortografía detectadas ({len(misspelled)})")
            
        suspicious_keywords = ['urgente', 'bloqueo', 'seguridad', 'verificar', 'cuenta', 'banco', 'pago', 'factura', 'premio', 'ganador', 'urgent', 'block', 'security', 'verify', 'account', 'bank', 'payment', 'invoice', 'prize', 'winner']
        found_keywords = [kw for kw in suspicious_keywords if kw.lower() in text_content.lower()]
        if found_keywords:
            email_risk_score += 20
            email_factors.append(f"Contenido sospechoso: {', '.join(found_keywords[:5])}")

        # Calcular riesgo máximo de URLs (usar todas las analizadas, no solo las filtradas)
        max_url_risk = 0
        for res in url_results_all:
            u_risk = res.get('risk_score', 0)
            if u_risk > max_url_risk: max_url_risk = u_risk
            if u_risk >= 30: email_factors.extend(res.get('risk_factors', []))

        email_risk_score = max(email_risk_score, max_url_risk)

        # --- EXTRACCIÓN REMITENTE FORENSE ---
        # 1. Recoger TODOS los emails del texto
        all_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text_content)
        # 2. Filtrar el del usuario y posibles duplicados técnicos
        blacklist = ["x4v1l0k@gmail.com", "safe_"] # safe_ es el prefijo de nuestros emails temporales
        
        sender_address = None
        for em in all_emails:
            if em.lower() not in blacklist and not em.lower().startswith("safe_"):
                sender_address = em
                break

        # 3. Refinamiento opcional: buscar específicamente después de "De:" en bloques de reenvío
        fwd_match = re.search(r'(?:de|from|enviado por):\s*.*<([\w\.-]+@[\w\.-]+\.\w+)>', text_content, re.IGNORECASE)
        if fwd_match:
            cand = fwd_match.group(1)
            if cand.lower() not in blacklist and not cand.lower().startswith("safe_"):
                sender_address = cand

        # Análisis paralelo con Google AI (no bloquea el análisis principal)
        ai_context = {
            "urls": [{"url": u.get("url", "")} for u in url_results[:10]]  # Primeras 10 URLs para contexto
        }
        ai_analysis = analyze_with_google_ai('email', content, context=ai_context)
        
        # Incorporar el riesgo del análisis de IA en el cálculo del riesgo total
        if ai_analysis and ai_analysis.get('enabled') and ai_analysis.get('risk_score', 0) > 0:
            ai_risk_score = ai_analysis.get('risk_score', 0)
            # Usar el máximo entre el riesgo calculado y el riesgo de la IA
            email_risk_score = max(email_risk_score, ai_risk_score)
            # Añadir factor de riesgo de IA si es significativo
            if ai_risk_score >= 30:
                ai_level = ai_analysis.get('risk_level', 'medio')
                ai_confidence = ai_analysis.get('confidence', 0)
                email_factors.append(f"Análisis de IA: {ai_risk_score}% de riesgo ({ai_level}) - Confianza: {ai_confidence}%")
        
        result = {
            "type": "email", 
            "email_risk_score": min(email_risk_score, 100),
            "email_factors": list(set(email_factors)), 
            "urls_found": url_results,
            "sender_address": sender_address,
            "spelling": {"total_words": len(words), "misspelled_count": len(misspelled), "misspelled_examples": list(misspelled)[:10]},
            "keywords_found": found_keywords,
            "ai_analysis": ai_analysis  # Análisis de IA en paralelo
        }
        
        # Guardar en caché
        save_to_cache(cache_key, result)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error en /analyze-email: {str(e)}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/analyze-sms', methods=['POST'])
@limiter.limit(f"{rate_limit_per_minute} per minute")
def analyze_sms():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type debe ser application/json"}), 400
        
        sender = request.json.get('sender', '')
        content = request.json.get('content', '')
        
        if not content or not isinstance(content, str):
            return jsonify({"error": "Contenido de SMS requerido"}), 400
        
        # Validar longitud máxima
        if len(content) > MAX_SMS_LENGTH:
            return jsonify({"error": f"Contenido de SMS demasiado largo (máximo {MAX_SMS_LENGTH} caracteres)"}), 400
        
        logger.info(f"Análisis de SMS solicitado (remitente: {sender[:20] if sender else 'N/A'})")
        
        # Verificar caché primero
        cache_key = get_cache_key_sms(sender, content)
        cached_result = get_from_cache(cache_key)
        if cached_result:
            logger.info(f"Devolviendo análisis de SMS desde caché")
            return jsonify(cached_result)
        
        # Extraer y expandir URLs
        urls = extract_urls(content)
        all_urls_to_analyze, url_expansions = expand_urls(urls)
        
        # Eliminar duplicados normalizados
        unique_urls = []
        seen_normalized = set()
        for u in all_urls_to_analyze:
            normalized = normalize_url(u)
            if normalized not in seen_normalized:
                unique_urls.append(u)
                seen_normalized.add(normalized)
        
        logger.info(f"Analizando {len(unique_urls)} URLs únicas en SMS (de {len(urls)} originales)")
        
        # Usar el mismo sistema de priorización que para emails
        url_preliminary = []
        for u in unique_urls:
            try:
                original_url = u
                unshortened = unshorten_url(u)
                is_shortened = (unshortened != original_url)
                if not unshortened.startswith(('http://', 'https://')):
                    unshortened = 'https://' + unshortened
                
                extracted = tldextract.extract(unshortened)
                domain = f"{extracted.domain}.{extracted.suffix}"
                hostname = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else domain
                
                # Filtrar dominios de confianza para ahorrar recursos
                if is_trusted_domain(domain) or is_trusted_domain(hostname):
                    logger.debug(f"Dominio de confianza ignorado: {domain} (URL: {unshortened[:50]}...)")
                    # Aún así crear una entrada con riesgo 0 para mantener consistencia
                    url_preliminary.append({
                        'url': unshortened,
                        'original_url': original_url,
                        'ssl_info': {'status': 'Legitimate Domain', 'valid': True},
                        'whois_info': {'is_recent': False, 'age_years': 10},
                        'priority': 0,  # Prioridad mínima
                        'is_shortened': is_shortened,
                        'domain': domain,
                        'hostname': hostname,
                        'is_legitimate': True
                    })
                    continue
                
                ssl_info = get_ssl_info(hostname)
                whois_info = get_domain_age(domain)
                priority = calculate_url_priority(unshortened, ssl_info, whois_info, is_shortened)
                
                url_preliminary.append({
                    'url': unshortened,
                    'original_url': original_url,
                    'ssl_info': ssl_info,
                    'whois_info': whois_info,
                    'priority': priority,
                    'is_shortened': is_shortened,
                    'domain': domain,
                    'hostname': hostname,
                    'is_legitimate': False
                })
            except Exception as e:
                logger.warning(f"Error en análisis preliminar de {u[:50]}: {str(e)}")
                continue
        
        # Ordenar por prioridad
        url_preliminary.sort(key=lambda x: x['priority'], reverse=True)
        
        # Analizar con servicios de reputación
        url_results_all = []
        for prelim in url_preliminary:
            try:
                # Saltar análisis costosos para dominios legítimos
                if prelim.get('is_legitimate', False):
                    result = {
                        "url": prelim['url'],
                        "original_url": prelim['original_url'],
                        "domain": prelim.get('hostname', prelim['domain']),
                        "base_domain": prelim['domain'],
                        "hostname": prelim.get('hostname', prelim['domain']),
                        "ssl": prelim['ssl_info'],
                        "whois": prelim['whois_info'],
                        "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "status": "Legitimate Domain", "detections": []},
                        "risk_score": 0,
                        "risk_factors": [],
                        "is_redirected": prelim['is_shortened']
                    }
                    url_results_all.append(result)
                    continue
                
                vt_info = check_url_reputation(prelim['url'])
                
                risk_score = 0
                risk_factors = []
                display_domain = prelim['hostname'] if prelim.get('hostname') else prelim['domain']
                
                if prelim['ssl_info'].get('status') != 'Secure':
                    risk_score += 30
                    risk_factors.append(f"[{display_domain}] SSL Inválido o inexistente")
                if prelim['whois_info'].get('is_recent'):
                    risk_score += 40
                    risk_factors.append(f"[{display_domain}] Dominio muy reciente")
                if vt_info.get('malicious', 0) > 0:
                    risk_score += 60
                    sources = vt_info.get('sources', ['Servicios de análisis'])
                    risk_factors.append(f"[{display_domain}] {', '.join(sources)}: {vt_info['malicious']} detección(es) maliciosa(s)")
                if any(service in prelim['domain'].lower() or service in prelim.get('hostname', '').lower() for service in HOSTING_SERVICES):
                    risk_score += 25
                    risk_factors.append(f"[{display_domain}] Enlace a servicio de alojamiento público")
                if prelim['is_shortened']:
                    risk_factors.append(f"URL acortada detectada. Destino: {prelim['url']}")
                
                result = {
                    "url": prelim['url'],
                    "original_url": prelim['original_url'],
                    "domain": display_domain,
                    "base_domain": prelim['domain'],
                    "hostname": prelim.get('hostname', prelim['domain']),
                    "ssl": prelim['ssl_info'],
                    "whois": prelim['whois_info'],
                    "virustotal": vt_info,
                    "risk_score": risk_score,
                    "risk_factors": risk_factors,
                    "is_redirected": prelim['is_shortened']
                }
                url_results_all.append(result)
            except Exception as e:
                logger.error(f"Error analizando URL {prelim['url'][:50]}: {str(e)}", exc_info=True)
                continue
        
        # Filtrar URLs con 0% de riesgo
        url_results = [r for r in url_results_all if r.get('risk_score', 0) > 0]
        logger.info(f"URLs con riesgo > 0%: {len(url_results)} (de {len(unique_urls)} analizadas)")
        
        # Análisis
        sms_keywords = ['paquete', 'entrega', 'correos', 'banco', 'bloqueada', 'verificar', 'premio', 'urgencia', 'transaccion', 'importe', 'codigo', 'movimiento', 'llame', 'atencion', 'seguridad', 'vencido', 'pago']
        found_kw = [kw for kw in sms_keywords if kw in content.lower()]
        
        phone_pattern = r'(?:\+|00)?(?:[0-9] ?){9,13}'
        found_phones = re.findall(phone_pattern, content)
        found_phones = [p.strip() for p in found_phones if len(re.sub(r'\D', '', p)) >= 9]
        
        # Reputación
        phone_rep = None
        target_phone = sender if re.sub(r'\D', '', sender) else (found_phones[0] if found_phones else None)
        if target_phone:
            phone_rep = check_phone_reputation(target_phone)

        risk_score = 0
        factors = []

        if found_kw:
            risk_score += 20 * min(len(found_kw), 3)
            factors.append(f"Palabras de urgencia/fraude: {', '.join(found_kw[:5])}")

        if found_phones:
            risk_score += 15
            factors.append(f"Número de contacto detectado en el texto: {found_phones[0]}")
        
        if phone_rep:
            status_l = phone_rep['status'].lower()
            
            factors.append(f"Reputación ListaSpam: {phone_rep['status']} ({phone_rep['reports']} denuncias)")
            if "peligroso" in status_l or "muy negativa" in status_l:
                risk_score += 70
            elif "irritante" in status_l or "negativa" in status_l:
                risk_score += 40
            
            if phone_rep['reports'] > 15: risk_score += 15

        for res in url_results:
            u_risk = res.get('risk_score', 0)
            risk_score = max(risk_score, u_risk)
            if u_risk >= 30:
                factors.extend(res.get('risk_factors', []))
        
        # Análisis paralelo con Google AI (no bloquea el análisis principal)
        ai_context = {
            "urls": [{"url": u.get("url", "")} for u in url_results[:10]]  # Primeras 10 URLs para contexto
        }
        ai_analysis = analyze_with_google_ai('sms', content, context=ai_context)
        
        # Incorporar el riesgo del análisis de IA en el cálculo del riesgo total
        if ai_analysis and ai_analysis.get('enabled') and ai_analysis.get('risk_score', 0) > 0:
            ai_risk_score = ai_analysis.get('risk_score', 0)
            # Usar el máximo entre el riesgo calculado y el riesgo de la IA
            risk_score = max(risk_score, ai_risk_score)
            # Añadir factor de riesgo de IA si es significativo
            if ai_risk_score >= 30:
                ai_level = ai_analysis.get('risk_level', 'medio')
                ai_confidence = ai_analysis.get('confidence', 0)
                factors.append(f"Análisis de IA: {ai_risk_score}% de riesgo ({ai_level}) - Confianza: {ai_confidence}%")
        
        result = {
            "type": "sms",
            "sender_phone": sender,
            "risk_score": min(risk_score, 100),
            "risk_factors": list(set(factors)),
            "urls_found": url_results,
            "keywords_found": found_kw,
            "found_phones": found_phones,
            "phone_reputation": phone_rep,
            "reputation_query": target_phone,
            "ai_analysis": ai_analysis  # Análisis de IA en paralelo
        }
        
        # Guardar en caché
        save_to_cache(cache_key, result)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error en /analyze-sms: {str(e)}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

MAIL_TM_URL = "https://api.mail.tm"
@app.route('/proxy/mailtm/domains', methods=['GET'])
def mailtm_domains():
    try:
        res = requests.get(f"{MAIL_TM_URL}/domains", headers=HEADERS, timeout=TIMEOUT_HTTP)
        if res.status_code != 200:
            return jsonify({"error": f"Error de API: {res.status_code}", "details": res.text[:200]}), res.status_code
        return jsonify(res.json())
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timeout al conectar con Mail.tm"}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "No se pudo conectar con Mail.tm. Verifica tu conexión."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/mailtm/create-account', methods=['POST'])
def mailtm_create_account():
    try:
        res = requests.post(f"{MAIL_TM_URL}/accounts", json=request.json, headers=HEADERS, timeout=TIMEOUT_HTTP)
        if res.status_code not in [200, 201]:
            error_data = res.json() if res.headers.get('content-type', '').startswith('application/json') else {}
            return jsonify({"error": error_data.get('message', f"Error {res.status_code}"), "details": error_data}), res.status_code
        return jsonify(res.json()), res.status_code
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timeout al crear cuenta"}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "No se pudo conectar con Mail.tm"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/mailtm/token', methods=['POST'])
def mailtm_token():
    try:
        res = requests.post(f"{MAIL_TM_URL}/token", json=request.json, headers=HEADERS, timeout=TIMEOUT_HTTP)
        if res.status_code != 200:
            error_data = res.json() if res.headers.get('content-type', '').startswith('application/json') else {}
            return jsonify({"error": error_data.get('message', f"Error {res.status_code}"), "details": error_data}), res.status_code
        return jsonify(res.json()), res.status_code
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timeout al obtener token"}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "No se pudo conectar con Mail.tm"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/mailtm/messages', methods=['GET'])
def mailtm_messages():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Token de autorización requerido"}), 401
        
        h = HEADERS.copy()
        h['Authorization'] = auth_header
        res = requests.get(f"{MAIL_TM_URL}/messages", headers=h, timeout=TIMEOUT_HTTP)
        
        if res.status_code == 401:
            return jsonify({"error": "Token inválido o expirado"}), 401
        elif res.status_code != 200:
            error_text = res.text[:200] if res.text else "Sin detalles"
            return jsonify({"error": f"Error {res.status_code}", "details": error_text}), res.status_code
        
        return jsonify(res.json())
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timeout al obtener mensajes"}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "No se pudo conectar con Mail.tm"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/mailtm/read-message', methods=['GET'])
def mailtm_read_message():
    try:
        h = HEADERS.copy(); h['Authorization'] = request.headers.get('Authorization')
        msg_id = request.args.get('id')
        if not msg_id:
            return jsonify({"error": "ID de mensaje requerido"}), 400
        res = requests.get(f"{MAIL_TM_URL}/messages/{msg_id}", headers=h, timeout=TIMEOUT_HTTP)
        if res.status_code != 200:
            return jsonify({"error": f"Error {res.status_code}", "details": res.text[:200]}), res.status_code
        return jsonify(res.json())
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timeout al leer mensaje"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cache/status', methods=['GET'])
def get_cache_status():
    """Obtiene el estado actual del switch de caché"""
    return jsonify({"enabled": CACHE_ENABLED})

@app.route('/api/cache/toggle', methods=['POST'])
def toggle_cache():
    """Activa o desactiva la caché"""
    global CACHE_ENABLED
    data = request.get_json() or {}
    CACHE_ENABLED = data.get('enabled', not CACHE_ENABLED)
    logger.info(f"Caché {'activada' if CACHE_ENABLED else 'desactivada'}")
    return jsonify({"enabled": CACHE_ENABLED})

# Inicializar la base de datos de caché al iniciar la aplicación
init_cache_db()

if __name__ == '__main__':
    flask_env = os.getenv('FLASK_ENV', 'development')
    flask_debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    flask_port = int(os.getenv('FLASK_PORT', '5000'))
    
    logger.info(f"Iniciando aplicación en modo {flask_env} (debug={flask_debug}) en puerto {flask_port}")
    app.run(debug=flask_debug, port=flask_port)
