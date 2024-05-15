# import hashlib
# import json
# hashed=hashlib.sha256()
# password=password.encode('ASCII')
#         hashed.update(password)
#         print(hashed.hexdigest())


from flask import Flask,jsonify,request
import os
import datetime
app= Flask(__name__)
import pymongo
from dotenv import load_dotenv,dotenv_values
from pymongo.mongo_client import MongoClient
# from pymongo.server_api import ServerApi
# from cryptography.fernet import Fernet
import base64
import rsa

load_dotenv()
# uri = "mongodb+srv://vasukotadiya224:ZnbujRS3Vm5sHJSz@cluster0.baqiyze.mongodb.net/oauth?retryWrites=true&w=majority&appName=Cluster0"
uri=os.getenv('MONGODB_URL')

client = MongoClient(uri)
db=client[os.getenv('DB_NAME')]
collectionandroid=db[os.getenv('COLLECTION_NAME1')]
collectiontoken=db[os.getenv('COLLECTION_NAME2')]



try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
    
    schema = {
    "bsonType": "object",
    "required": ["package_name", "redirect_url", "weboauth_url"],
    "properties": {
        "package_name": {
            "bsonType": "string",
            "description": "must be a string and is required"
        },
        "redirect_url": {
            "bsonType": "string",
            "description": "must be a string and is required"
        },
        "weboauth_url": {
            "bsonType": "string",
            "description": "must be a string and is required"
        }
    }
}   
    schema2 = {
    "bsonType": "object",
    "required": ["token"],
    "properties": {
        "token": {
            "bsonType": "string",
            "description": "must be a string and is required"
        }
    }
}
    
    try:
        db.create_collection("android", validator={"$jsonSchema": schema})
        print("Collection created with schema validation")
    except pymongo.errors.CollectionInvalid:
        print("Collection already exists")
    
    try:
        db.create_collection("token", validator={"$jsonSchema": schema2})
        print("Collection created with schema validation")
    except pymongo.errors.CollectionInvalid:
        print("Collection already exists")
        
        


    
except Exception as e:
    print(e)


# def upload(data,collectionname):
#     try:
#         x=collectionname.insert_one(data)
#         print("Document inserted successfully")
#         print(x.inserted_id)
#     except pymongo.errors.WriteError as e:
#         print("Document insertion failed:", e)
        
# def retrive(data,collectionname):
#     try:
#         results = db.user.find({"package_name": data.package_name, "redirect_url": data.redirect_url})
#         for result in results:
#             print("Retrieved document:", result)
#     except pymongo.errors.PyMongoError as e:
#         print("Document retrieval failed:", e)



@app.route('/upload',methods=['GET'])
def post_upload():
        data={
        "_id":request.headers.get('_id'),
        "package_name":request.headers.get('package_name'),
        "redirect_url":request.headers.get('redirect_url'),
        "weboauth_url":request.headers.get('weboauth_url'),
        }
        try:
            x=collectionandroid.insert_one(data)
            print("Document inserted successfully")
            print(x.inserted_id)
        except pymongo.errors.WriteError as e:
            print("Document insertion failed:", e)
        return "success"
        
@app.route('/getdata',methods=['GET'])
def get_data():
    redirect_url=request.headers.get('redirect_url')
    try:
        results = collectionandroid.find({"redirect_url": redirect_url})
        for result in results:
            print("Retrieved document:", result)
            data=dict(result)
            # genrateAccessToken(data)
            time=str(int(datetime.datetime.utcnow().timestamp())+30000)
            weboauth_url=data.get('_id')
            token=(weboauth_url+"$"+time+"$"+data.get("redirect_url")).encode('ASCII')
            cipher = rsa.encrypt(token, publicKey)
            base64Text = base64.b64encode(cipher).decode()
            data['accessToken']=base64Text
            print(data)
            try:
                collectiontoken.insert_one({'token':base64Text})
                return data
            except pymongo.errors.WriteError as e:
                print("Document insertion failed:", e)
                return False
            # return data
        
        
        
        
        

    except pymongo.errors.PyMongoError as e:
        print("Document retrieval failed:", e)
        return str(e)

    
    

# def genrateKey():
#     publicKey, privateKey = rsa.newkeys(128)
#     return publicKey, privateKey
# publicKey, privateKey=genrateKey()

# data={
#     'package_name':'com.vasukotadiya.exampleapp',
#     'redirect_url':'app://login',
#     'weboauth_url':'https://weboauth.vasukotadiya.site',
#     '_id':'s2fd56wff31'
# }

privateKey=rsa.key.PrivateKey(7587312699188860924676781532146918575939057770410210951116836398204515474978363609689786219334393896768383157793015320920292955260624113834822137985270727, 65537, 1834629970002378489606679538885396320748680111809979293259509992864289739340363314862220455748778605772054939688710664305854904491597658045354888324668169, 5353236419143575549061381287557169746363882761856136414797653862316005264102608403, 1417331891424795061001257925698140522299291715848479451031757915333171709)
publicKey=rsa.key.PublicKey(7587312699188860924676781532146918575939057770410210951116836398204515474978363609689786219334393896768383157793015320920292955260624113834822137985270727, 65537)

def genrateAccessToken(data):
    time=str(int(datetime.datetime.utcnow().timestamp())+30000)
    weboauth_url=data.get('_id')
    token=(weboauth_url+"$"+time+"$"+data.get("redirect_url")).encode('ASCII')
    cipher = rsa.encrypt(token, publicKey)
    base64Text = base64.b64encode(cipher).decode()
    data['accessToken']=base64Text
    print(data)
    return data
    # try:
    #     collectiontoken.insert_one({'token':base64Text})
    #     return data
    # except pymongo.errors.WriteError as e:
    #     print("Document insertion failed:", e)
    #     return False
    
# genrateAccessToken(data)
@app.route('/validatetoken',methods=['GET'])
def validateToken():
    # try:
    #     x=collectiontoken.find({'token':accessToken})
    #     if(x==None):
    #         return "Invalid Token"
    # except pymongo.errors.PyMongoError as e:
    #     print("Document retrieval failed:", e)
    #     return e
    accessToken=request.headers.get('accessToken')
    try:
        text = rsa.decrypt(base64.b64decode(accessToken.encode()), privateKey)
    except rsa.pkcs1.DecryptionError as e:
        print("invalid token decryption failed")
        return "INVALID TOKEN"  
    print(text.decode())
    token=text.decode()
    token=token.split("$")
    appid,time,redirect=token[0],token[1],token[2]
    time=int(time)
    if(datetime.datetime.utcnow().timestamp()>time):
        return "Timed Out"
    return {'time':time,'redirect':redirect}

if __name__ == '__main__':
    app.run(port=3000)
