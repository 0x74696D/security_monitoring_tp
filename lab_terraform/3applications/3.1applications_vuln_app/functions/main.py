import os
import json
import uuid
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any
import traceback

import functions_framework
from flask import Request, jsonify, Response
from google.cloud import storage, firestore
import google.auth
from google.auth.transport import requests as google_requests
import firebase_admin
from firebase_admin import auth, credentials
from werkzeug.utils import secure_filename

# Configure structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Firebase Admin
try:
    firebase_admin.initialize_app()
except ValueError:
    pass  # Already initialized

# Environment configuration
PROJECT_ID = os.environ.get('PROJECT_ID')
BUCKET_NAME = os.environ.get('BUCKET_NAME')
ENABLE_FIRESTORE = os.environ.get('ENABLE_FIRESTORE', 'true').lower() == 'true'
LAB_MODE_SKIP_OWNERSHIP = os.environ.get('LAB_MODE_SKIP_OWNERSHIP_CHECK', 'false').lower() == 'true'
LAB_MODE_WEAK_TOKEN = os.environ.get('LAB_MODE_WEAK_TOKEN_VALIDATION', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'lab')

# Initialize clients
storage_client = storage.Client()
bucket = storage_client.bucket(BUCKET_NAME)
db = firestore.Client() if ENABLE_FIRESTORE else None

# In-memory store when Firestore is disabled (for demo only)
memory_store = {
    'images': {},  # imageId -> {owner_uid, storage_path, created_at, email}
    'users': {}    # uid -> {admin: bool, email: str}
}

# Allowed image extensions
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}


class SecurityLogger:
    """Structured security event logger for Cloud Logging"""
    
    @staticmethod
    def log_event(
        event_type: str,
        user_id: Optional[str],
        email: Optional[str],
        source_ip: str,
        endpoint: str,
        method: str,
        result: str,
        reason: str,
        severity: str = "INFO",
        resource_identifiers: Optional[Dict] = None,
        request_id: Optional[str] = None,
        **extra_fields
    ):
        """
        Log a security event in structured JSON format
        
        Args:
            event_type: access, upload, download, delete, admin_access, auth_audit
            user_id: JWT sub (user ID)
            email: User email
            source_ip: Client IP address
            endpoint: API endpoint path
            method: HTTP method
            result: allowed, denied, success, failure
            reason: unauthorized, not_found, validation_error, lab_mode, etc.
            severity: INFO, WARNING, ERROR
            resource_identifiers: Dict with imageId, bucket, object_path, etc.
            request_id: Request/trace ID
        """
        log_entry = {
            "event_type": event_type,
            "user_id": user_id,
            "email": email,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "method": method,
            "result": result,
            "reason": reason,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "environment": ENVIRONMENT,
            "request_id": request_id or str(uuid.uuid4()),
        }
        
        if resource_identifiers:
            log_entry["resource_identifiers"] = resource_identifiers
        
        # Add any extra fields
        log_entry.update(extra_fields)
        
        # Log to stdout for Cloud Logging ingestion
        log_message = json.dumps(log_entry)
        
        if severity == "ERROR":
            logger.error(log_message)
        elif severity == "WARNING":
            logger.warning(log_message)
        else:
            logger.info(log_message)


def get_source_ip(request: Request) -> str:
    """Extract source IP from request headers"""
    # Try X-Forwarded-For first (set by API Gateway/Load Balancer)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Return first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    # Fallback to remote_addr
    return request.remote_addr or 'unknown'


def verify_token(request: Request) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Verify Firebase ID token from Authorization header
    
    Returns:
        (decoded_token, error_message)
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None, "Missing or invalid Authorization header"
    
    token = auth_header.split('Bearer ')[1]
    
    if not token:
        return None, "Empty token"
    
    # LAB MODE: Weak token validation
    if LAB_MODE_WEAK_TOKEN:
        # Minimal sanity check only - INSECURE BY DESIGN
        if len(token) < 10:
            return None, "Token too short"
        
        # Parse token without verification (DANGEROUS!)
        try:
            import base64
            parts = token.split('.')
            if len(parts) != 3:
                return None, "Invalid token format"
            
            # Decode payload (second part)
            payload = parts[1]
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)
            
            # Log that we're using weak validation
            SecurityLogger.log_event(
                event_type="auth_audit",
                user_id=claims.get('sub', 'unknown'),
                email=claims.get('email', 'unknown'),
                source_ip=get_source_ip(request),
                endpoint=request.path,
                method=request.method,
                result="allowed",
                reason="lab_mode_weak_validation",
                severity="WARNING",
                lab_mode="weak_token_validation"
            )
            
            return claims, None
        except Exception as e:
            return None, f"Token decode error: {str(e)}"
    
    # Normal path: Proper Firebase token verification
    # Use custom verification that works with Identity Platform
    try:
        import jwt
        import requests
        from datetime import datetime
        
        # Decode without verification first to check basic structure
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return None, f"Malformed token: {str(e)}"
        
        # Check expiration
        exp = unverified.get('exp')
        if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
            return None, "Token expired"
        
        # Check issuer (accept both Firebase and Google accounts issuers)
        iss = unverified.get('iss')
        valid_issuers = [
            f"https://securetoken.google.com/{PROJECT_ID}",
            "https://accounts.google.com"
        ]
        if not iss or iss not in valid_issuers:
            return None, f"Invalid issuer: {iss}"
        
        # Get public keys (try Firebase first, then Google OAuth2)
        try:
            # Try Firebase keys first
            certs_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
            response = requests.get(certs_url, timeout=5)
            response.raise_for_status()
            certs = response.json()
            
            # Get key ID from token header
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            
            # If key not in Firebase certs, try Google OAuth2 certs
            if kid and kid not in certs:
                certs_url = "https://www.googleapis.com/oauth2/v1/certs"
                response = requests.get(certs_url, timeout=5)
                response.raise_for_status()
                certs = response.json()
                
        except Exception as e:
            return None, f"Failed to fetch verification keys: {str(e)}"
        
        if not kid or kid not in certs:
            # Try to use firebase-admin as fallback
            try:
                decoded_token = auth.verify_id_token(token, check_revoked=False)
                return decoded_token, None
            except Exception:
                return None, f"Key ID not found: {kid}"
        
        # Get the certificate for this key
        cert = certs[kid]
        
        # Verify signature and decode
        try:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.backends import default_backend
            
            # Load the certificate and extract public key
            cert_obj = load_pem_x509_certificate(cert.encode(), default_backend())
            public_key = cert_obj.public_key()
            
            # Try with Firebase issuer first
            try:
                decoded = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},  # Don't verify audience
                    issuer=f"https://securetoken.google.com/{PROJECT_ID}"
                )
            except jwt.InvalidIssuerError:
                # Try with Google accounts issuer
                decoded = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},  # Don't verify audience
                    issuer="https://accounts.google.com"
                )
        except jwt.ExpiredSignatureError:
            return None, "Token expired"
        except jwt.InvalidTokenError as e:
            return None, f"Invalid token: {str(e)}"
        
        # Validate required claims
        if not decoded.get('sub'):
            return None, "Missing subject claim"
        
        return decoded, None
        
    except Exception as e:
        # Final fallback: try firebase-admin
        try:
            decoded_token = auth.verify_id_token(token, check_revoked=False)
            return decoded_token, None
        except Exception:
            return None, f"Token verification failed: {str(e)}"


def is_admin(user_id: str, email: str) -> bool:
    """Check if user has admin privileges"""
    
    if ENABLE_FIRESTORE and db:
        # Check Firestore for admin role
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            data = user_doc.to_dict()
            return data.get('admin', False)
        
        # Default: first user or specific email patterns are admin
        # In production, this should be explicitly set
        return False
    else:
        # Memory store fallback
        user_data = memory_store['users'].get(user_id, {})
        return user_data.get('admin', False)


def store_image_metadata(image_id: str, user_id: str, email: str, storage_path: str):
    """Store image metadata in Firestore or memory"""
    
    metadata = {
        'owner_uid': user_id,
        'email': email,
        'storage_path': storage_path,
        'created_at': datetime.utcnow().isoformat() + "Z"
    }
    
    if ENABLE_FIRESTORE and db:
        db.collection('images').document(image_id).set(metadata)
    else:
        memory_store['images'][image_id] = metadata


def get_image_metadata(image_id: str) -> Optional[Dict]:
    """Retrieve image metadata"""
    
    if ENABLE_FIRESTORE and db:
        doc = db.collection('images').document(image_id).get()
        if doc.exists:
            return doc.to_dict()
        return None
    else:
        return memory_store['images'].get(image_id)


def delete_image_metadata(image_id: str):
    """Delete image metadata"""
    
    if ENABLE_FIRESTORE and db:
        db.collection('images').document(image_id).delete()
    else:
        memory_store['images'].pop(image_id, None)


def list_user_images(user_id: str) -> list:
    """List all images for a user"""
    
    if ENABLE_FIRESTORE and db:
        images = []
        docs = db.collection('images').where('owner_uid', '==', user_id).stream()
        for doc in docs:
            data = doc.to_dict()
            data['image_id'] = doc.id
            images.append(data)
        return images
    else:
        return [
            {'image_id': img_id, **data}
            for img_id, data in memory_store['images'].items()
            if data['owner_uid'] == user_id
        ]


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ============= ENDPOINT HANDLERS =============

def handle_health(request: Request) -> Tuple[Dict, int]:
    """Health check endpoint"""
    
    SecurityLogger.log_event(
        event_type="access",
        user_id=None,
        email=None,
        source_ip=get_source_ip(request),
        endpoint="/health",
        method="GET",
        result="success",
        reason="health_check",
        severity="INFO"
    )
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "environment": ENVIRONMENT,
        "firestore_enabled": ENABLE_FIRESTORE
    }, 200


def handle_auth_audit(request: Request) -> Tuple[Dict, int]:
    """Log authentication events"""
    
    try:
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        outcome = data.get('outcome')
        email = data.get('email', 'unknown')
        
        if not action or not outcome:
            return {"error": "Missing action or outcome"}, 400
        
        # Try to get user_id from token if provided
        user_id = None
        token_data, _ = verify_token(request)
        if token_data:
            user_id = token_data.get('sub')
            email = token_data.get('email', email)
        
        SecurityLogger.log_event(
            event_type="auth_audit",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint="/auth/audit",
            method="POST",
            result=outcome,
            reason=f"{action}_{outcome}",
            severity="WARNING" if outcome == "failure" else "INFO",
            action=action
        )
        
        return {"message": "Audit logged"}, 200
        
    except Exception as e:
        return {"error": str(e)}, 500


def handle_profile(request: Request, token_data: Dict) -> Tuple[Dict, int]:
    """Get user profile"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    SecurityLogger.log_event(
        event_type="access",
        user_id=user_id,
        email=email,
        source_ip=get_source_ip(request),
        endpoint="/profile",
        method="GET",
        result="success",
        reason="authorized",
        severity="INFO"
    )
    
    profile = {
        "user_id": user_id,
        "email": email,
        "created_at": token_data.get('auth_time'),
        "is_admin": is_admin(user_id, email)
    }
    
    return profile, 200


def handle_upload_image(request: Request, token_data: Dict) -> Tuple[Dict, int]:
    """Upload image to Cloud Storage"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    try:
        # Check if file is in request
        if 'image' not in request.files:
            SecurityLogger.log_event(
                event_type="upload",
                user_id=user_id,
                email=email,
                source_ip=get_source_ip(request),
                endpoint="/images/upload",
                method="POST",
                result="failure",
                reason="no_file_provided",
                severity="WARNING"
            )
            return {"error": "No image file provided"}, 400
        
        file = request.files['image']
        
        if file.filename == '':
            return {"error": "Empty filename"}, 400
        
        if not allowed_file(file.filename):
            SecurityLogger.log_event(
                event_type="upload",
                user_id=user_id,
                email=email,
                source_ip=get_source_ip(request),
                endpoint="/images/upload",
                method="POST",
                result="failure",
                reason="invalid_file_type",
                severity="WARNING",
                filename=file.filename
            )
            return {"error": "Invalid file type"}, 400
        
        # Generate unique image ID (semi-predictable for lab realism)
        image_id = str(uuid.uuid4())[:8]  # Short UUID for lab purposes
        
        # Secure filename
        original_filename = secure_filename(file.filename)
        extension = original_filename.rsplit('.', 1)[1].lower()
        
        # Storage path: users/{uid}/{imageId}.{ext}
        storage_path = f"users/{user_id}/{image_id}.{extension}"
        
        # Upload to Cloud Storage
        blob = bucket.blob(storage_path)
        blob.upload_from_file(file, content_type=file.content_type)
        
        # Store metadata
        store_image_metadata(image_id, user_id, email, storage_path)
        
        SecurityLogger.log_event(
            event_type="upload",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint="/images/upload",
            method="POST",
            result="success",
            reason="file_uploaded",
            severity="INFO",
            resource_identifiers={
                "image_id": image_id,
                "bucket": BUCKET_NAME,
                "object_path": storage_path
            }
        )
        
        return {
            "image_id": image_id,
            "storage_path": storage_path,
            "upload_time": datetime.utcnow().isoformat() + "Z"
        }, 200
        
    except Exception as e:
        SecurityLogger.log_event(
            event_type="upload",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint="/images/upload",
            method="POST",
            result="failure",
            reason="internal_error",
            severity="ERROR",
            error=str(e)
        )
        return {"error": f"Upload failed: {str(e)}"}, 500


def handle_get_image(request: Request, token_data: Dict, image_id: str) -> Tuple[Dict, int]:
    """Get image signed URL with ownership check"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    # Get image metadata
    metadata = get_image_metadata(image_id)
    
    if not metadata:
        SecurityLogger.log_event(
            event_type="download",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="GET",
            result="denied",
            reason="not_found",
            severity="WARNING",
            resource_identifiers={"image_id": image_id}
        )
        return {"error": "Image not found"}, 404
    
    owner_uid = metadata.get('owner_uid')
    storage_path = metadata.get('storage_path')
    
    # LAB MODE: Skip ownership check
    if LAB_MODE_SKIP_OWNERSHIP:
        SecurityLogger.log_event(
            event_type="download",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="GET",
            result="allowed",
            reason="lab_mode_skip_ownership",
            severity="WARNING",
            resource_identifiers={
                "image_id": image_id,
                "bucket": BUCKET_NAME,
                "object_path": storage_path,
                "actual_owner": owner_uid
            },
            lab_mode="skip_ownership_check",
            vulnerability="IDOR"
        )
    else:
        # Normal path: Check ownership
        if owner_uid != user_id:
            SecurityLogger.log_event(
                event_type="download",
                user_id=user_id,
                email=email,
                source_ip=get_source_ip(request),
                endpoint=f"/images/{image_id}",
                method="GET",
                result="denied",
                reason="unauthorized_not_owner",
                severity="WARNING",
                resource_identifiers={
                    "image_id": image_id,
                    "bucket": BUCKET_NAME,
                    "object_path": storage_path,
                    "actual_owner": owner_uid
                }
            )
            return {"error": "Forbidden: You don't own this image"}, 403
        
        SecurityLogger.log_event(
            event_type="download",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="GET",
            result="allowed",
            reason="authorized_owner",
            severity="INFO",
            resource_identifiers={
                "image_id": image_id,
                "bucket": BUCKET_NAME,
                "object_path": storage_path
            }
        )
    
    # Generate signed URL (valid for 15 minutes)
    blob = bucket.blob(storage_path)
    signed_url = blob.generate_signed_url(
        version="v4",
        expiration=timedelta(minutes=15),
        method="GET"
    )
    
    return {
        "signed_url": signed_url,
        "image_id": image_id,
        "metadata": metadata
    }, 200


def handle_delete_image(request: Request, token_data: Dict, image_id: str) -> Tuple[Dict, int]:
    """Delete image with ownership check"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    # Get image metadata
    metadata = get_image_metadata(image_id)
    
    if not metadata:
        SecurityLogger.log_event(
            event_type="delete",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="DELETE",
            result="denied",
            reason="not_found",
            severity="WARNING",
            resource_identifiers={"image_id": image_id}
        )
        return {"error": "Image not found"}, 404
    
    owner_uid = metadata.get('owner_uid')
    storage_path = metadata.get('storage_path')
    
    # LAB MODE: Skip ownership check
    if LAB_MODE_SKIP_OWNERSHIP:
        SecurityLogger.log_event(
            event_type="delete",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="DELETE",
            result="allowed",
            reason="lab_mode_skip_ownership",
            severity="WARNING",
            resource_identifiers={
                "image_id": image_id,
                "bucket": BUCKET_NAME,
                "object_path": storage_path,
                "actual_owner": owner_uid
            },
            lab_mode="skip_ownership_check",
            vulnerability="IDOR"
        )
    else:
        # Normal path: Check ownership
        if owner_uid != user_id:
            SecurityLogger.log_event(
                event_type="delete",
                user_id=user_id,
                email=email,
                source_ip=get_source_ip(request),
                endpoint=f"/images/{image_id}",
                method="DELETE",
                result="denied",
                reason="unauthorized_not_owner",
                severity="WARNING",
                resource_identifiers={
                    "image_id": image_id,
                    "bucket": BUCKET_NAME,
                    "object_path": storage_path,
                    "actual_owner": owner_uid
                }
            )
            return {"error": "Forbidden: You don't own this image"}, 403
        
        SecurityLogger.log_event(
            event_type="delete",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint=f"/images/{image_id}",
            method="DELETE",
            result="allowed",
            reason="authorized_owner",
            severity="INFO",
            resource_identifiers={
                "image_id": image_id,
                "bucket": BUCKET_NAME,
                "object_path": storage_path
            }
        )
    
    # Delete from storage
    blob = bucket.blob(storage_path)
    blob.delete()
    
    # Delete metadata
    delete_image_metadata(image_id)
    
    return {
        "message": "Image deleted successfully",
        "image_id": image_id
    }, 200


def handle_export(request: Request, token_data: Dict) -> Tuple[Dict, int]:
    """Export user's image metadata"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    images = list_user_images(user_id)
    
    SecurityLogger.log_event(
        event_type="access",
        user_id=user_id,
        email=email,
        source_ip=get_source_ip(request),
        endpoint="/export",
        method="GET",
        result="success",
        reason="data_export",
        severity="INFO",
        exported_count=len(images)
    )
    
    return {
        "user_id": user_id,
        "email": email,
        "export_time": datetime.utcnow().isoformat() + "Z",
        "images": images
    }, 200


def handle_admin(request: Request, token_data: Dict) -> Tuple[Dict, int]:
    """Admin-only endpoint"""
    
    user_id = token_data['sub']
    email = token_data.get('email', 'unknown')
    
    # Check admin privileges
    if not is_admin(user_id, email):
        SecurityLogger.log_event(
            event_type="admin_access",
            user_id=user_id,
            email=email,
            source_ip=get_source_ip(request),
            endpoint="/admin",
            method="GET",
            result="denied",
            reason="not_admin",
            severity="WARNING"
        )
        return {"error": "Forbidden: Admin access required"}, 403
    
    SecurityLogger.log_event(
        event_type="admin_access",
        user_id=user_id,
        email=email,
        source_ip=get_source_ip(request),
        endpoint="/admin",
        method="GET",
        result="allowed",
        reason="admin_authorized",
        severity="INFO"
    )
    
    # Gather stats
    if ENABLE_FIRESTORE and db:
        total_images = len(list(db.collection('images').stream()))
        total_users = len(list(db.collection('users').stream()))
    else:
        total_images = len(memory_store['images'])
        total_users = len(memory_store['users'])
    
    return {
        "message": "Admin dashboard",
        "stats": {
            "total_images": total_images,
            "total_users": total_users,
            "bucket": BUCKET_NAME,
            "environment": ENVIRONMENT,
            "firestore_enabled": ENABLE_FIRESTORE
        }
    }, 200


# ============= MAIN REQUEST HANDLER =============

@functions_framework.http
def handle_request(request: Request):
    """Main request handler for all endpoints"""
    
    # CORS headers
    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type',
            'Access-Control-Max-Age': '3600'
        }
        return ('', 204, headers)
    
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    }
    
    try:
        path = request.path
        method = request.method
        
        # Public endpoints (no auth required)
        if path == '/health' and method == 'GET':
            response, status = handle_health(request)
            return (jsonify(response), status, headers)
        
        if path == '/auth/audit' and method == 'POST':
            response, status = handle_auth_audit(request)
            return (jsonify(response), status, headers)
        
        # Protected endpoints - verify token
        token_data, error = verify_token(request)
        
        if error:
            SecurityLogger.log_event(
                event_type="access",
                user_id=None,
                email=None,
                source_ip=get_source_ip(request),
                endpoint=path,
                method=method,
                result="denied",
                reason="invalid_token",
                severity="WARNING",
                error=error
            )
            return (jsonify({"error": f"Unauthorized: {error}"}), 401, headers)
        
        # Route to handlers
        if path == '/profile' and method == 'GET':
            response, status = handle_profile(request, token_data)
        
        elif path == '/images/upload' and method == 'POST':
            response, status = handle_upload_image(request, token_data)
        
        elif path.startswith('/images/') and method == 'GET':
            image_id = path.split('/images/')[1]
            response, status = handle_get_image(request, token_data, image_id)
        
        elif path.startswith('/images/') and method == 'DELETE':
            image_id = path.split('/images/')[1]
            response, status = handle_delete_image(request, token_data, image_id)
        
        elif path == '/export' and method == 'GET':
            response, status = handle_export(request, token_data)
        
        elif path == '/admin' and method == 'GET':
            response, status = handle_admin(request, token_data)
        
        else:
            SecurityLogger.log_event(
                event_type="access",
                user_id=token_data.get('sub'),
                email=token_data.get('email'),
                source_ip=get_source_ip(request),
                endpoint=path,
                method=method,
                result="denied",
                reason="not_found",
                severity="WARNING"
            )
            response, status = {"error": "Not found"}, 404
        
        return (jsonify(response), status, headers)
    
    except Exception as e:
        error_trace = traceback.format_exc()
        SecurityLogger.log_event(
            event_type="access",
            user_id=None,
            email=None,
            source_ip=get_source_ip(request),
            endpoint=request.path,
            method=request.method,
            result="failure",
            reason="internal_error",
            severity="ERROR",
            error=str(e),
            trace=error_trace
        )
        return (jsonify({"error": "Internal server error"}), 500, headers)

