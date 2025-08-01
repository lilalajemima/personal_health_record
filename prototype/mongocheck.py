import pymongo
from pymongo.errors import ConnectionFailure, ConfigurationError

def check_mongodb_connection(connection_string, db_name=None):
    """
    Check if a connection to MongoDB can be established.
    
    Args:
        connection_string (str): MongoDB connection URI
        db_name (str, optional): Database name to test connection to
        
    Returns:
        tuple: (bool: success, str: message)
    """
    try:
        # Create MongoClient
        client = pymongo.MongoClient(connection_string, serverSelectionTimeoutMS=5000)
        
        # Try to get server info to verify connection
        client.server_info()
        
        # If a database name was provided, try to access it
        if db_name:
            db = client[db_name]
            # Perform a simple operation like listing collections
            db.list_collection_names()
            
        return True, "Successfully connected to MongoDB!"
        
    except ConfigurationError as e:
        return False, f"Configuration error: {str(e)}"
    except ConnectionFailure as e:
        return False, f"Failed to connect to MongoDB: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

if __name__ == "__main__":
    print("MongoDB Connection Checker")
    print("-------------------------")
    
    # Get connection details from user
    connection_string = input("Enter your MongoDB connection string: ").strip()
    db_name = input("Enter database name to test (optional, press Enter to skip): ").strip() or None
    
    # Test the connection
    success, message = check_mongodb_connection(connection_string, db_name)
    
    # Print results
    print("\nResults:")
    print("✅" if success else "❌", message)