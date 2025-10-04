from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from functools import wraps
import firebase_admin_setup as firebase
from config import config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(config['default'])

# Initialize Firebase
if not firebase.initialize_firebase():
    print("Failed to initialize Firebase Admin SDK")

# Swagger UI Configuration
api = Api(
    app, 
    version='1.0', 
    title='Firebase Auth API',
    description='A Flask API with Firebase Authentication and Security Pass Verification',
    doc='/swagger/'
)

# Swagger Models
auth_model = api.model('Auth', {
    'token': fields.String(required=True, description='Firebase ID Token'),
    'required_pass': fields.String(
        required=False, 
        description='Required security pass level (basic, standard, premium, admin)',
        default='basic'
    )
})

user_model = api.model('User', {
    'uid': fields.String(description='User ID'),
    'email': fields.String(description='User Email'),
    'pass_level': fields.String(description='Security pass level')
})

# Authentication Decorator
def token_required(required_pass="basic"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'error': 'Authorization header missing or invalid'}, 401
            
            token = auth_header.split('Bearer ')[1]
            
            # Verify token
            decoded_token = firebase.verify_firebase_token(token)
            if not decoded_token:
                return {'error': 'Invalid or expired token'}, 401
            
            # Check security pass
            if not firebase.check_security_pass(decoded_token, required_pass):
                return {'error': f'Insufficient security pass level. Required: {required_pass}'}, 403
            
            # Add user info to request context
            request.user = {
                'uid': decoded_token.get('uid'),
                'email': decoded_token.get('email'),
                'pass_level': decoded_token.get('claims', {}).get('pass_level', 'basic')
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Root route
@app.route('/')
def home():
    """Root endpoint with API information"""
    return {
        'message': 'Firebase Auth API is running',
        'version': '1.0',
        'endpoints': {
            'swagger_docs': '/swagger/',
            'health_check': '/health',
            'verify_token': '/auth/verify',
            'protected_basic': '/protected/basic',
            'protected_premium': '/protected/premium',
            'protected_admin': '/protected/admin'
        }
    }, 200

# API Routes
@api.route('/auth/verify')
class VerifyToken(Resource):
    @api.expect(auth_model)
    @api.response(200, 'Success', user_model)
    @api.response(401, 'Unauthorized')
    @api.response(403, 'Forbidden')
    def post(self):
        """Verify Firebase token and check security pass"""
        data = request.get_json()
        
        token = data.get('token')
        required_pass = data.get('required_pass', 'basic')
        
        if not token:
            return {'error': 'Token is required'}, 400
        
        # Verify token
        decoded_token = firebase.verify_firebase_token(token)
        if not decoded_token:
            return {'error': 'Invalid or expired token'}, 401
        
        # Check security pass
        if not firebase.check_security_pass(decoded_token, required_pass):
            return {'error': f'Insufficient security pass level. Required: {required_pass}'}, 403
        
        return {
            'uid': decoded_token.get('uid'),
            'email': decoded_token.get('email'),
            'pass_level': decoded_token.get('claims', {}).get('pass_level', 'basic'),
            'message': 'Token verified successfully'
        }, 200

@api.route('/protected/basic')
class BasicProtected(Resource):
    @api.doc(security='Bearer Auth')
    @token_required(required_pass="basic")
    def get(self):
        """Basic level protected endpoint"""
        return {
            'message': 'Access granted to basic protected resource',
            'user': request.user
        }, 200

@api.route('/protected/premium')
class PremiumProtected(Resource):
    @api.doc(security='Bearer Auth')
    @token_required(required_pass="premium")
    def get(self):
        """Premium level protected endpoint"""
        return {
            'message': 'Access granted to premium protected resource',
            'user': request.user
        }, 200

@api.route('/protected/admin')
class AdminProtected(Resource):
    @api.doc(security='Bearer Auth')
    @token_required(required_pass="admin")
    def get(self):
        """Admin level protected endpoint"""
        return {
            'message': 'Access granted to admin protected resource',
            'user': request.user
        }, 200

@api.route('/health')
class HealthCheck(Resource):
    def get(self):
        """Health check endpoint"""
        return {
            'status': 'healthy',
            'firebase_initialized': bool(firebase_admin._apps)
        }, 200

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)