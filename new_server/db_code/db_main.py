import pymongo

# Establish a connection to the local MongoDB instance
client = pymongo.MongoClient("mongodb://localhost:27017/")

# Create a new database
PeerbrainDB = client["peerbrain_db"]

