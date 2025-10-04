import firebase_admin
from firebase_admin import credentials, auth
from config import Config

def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    try:
        # Check if Firebase app is already initialized
        if not firebase_admin._apps:
            cred = credentials.Certificate("firebase-service-account.json")
            firebase_admin.initialize_app(cred, {
                'projectId': Config.FIREBASE_PROJECT_ID,
                'databaseURL': Config.FIREBASE_DATABASE_URL
            })
            print("Firebase Admin SDK initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing Firebase: {str(e)}")
        return False

def verify_firebase_token(id_token):
    """
    Verify Firebase ID token
    Returns: Decoded token if valid, None if invalid
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except auth.InvalidIdTokenError:
        print("Invalid ID token")
        return None
    except auth.ExpiredIdTokenError:
        print("Expired ID token")
        return None
    except auth.RevokedIdTokenError:
        print("Revoked ID token")
        return None
    except auth.CertificateFetchError:
        print("Error fetching certificate")
        return None
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        return None

def check_security_pass(decoded_token, required_pass_level="premium"):
    """
    Check if user has required security pass level
    You can customize this based on your user roles/claims
    """
    try:
        # Check custom claims in the token
        custom_claims = decoded_token.get('claims', {})
        user_pass_level = custom_claims.get('pass_level', 'basic')
        
        # Define pass hierarchy
        pass_hierarchy = {
            'basic': 1,
            'standard': 2,
            'premium': 3,
            'admin': 4
        }
        
        user_level = pass_hierarchy.get(user_pass_level, 0)
        required_level = pass_hierarchy.get(required_pass_level, 0)
        
        return user_level >= required_level
    except Exception as e:
        print(f"Error checking security pass: {str(e)}")
        return False