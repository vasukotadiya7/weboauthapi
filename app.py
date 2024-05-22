# import hashlib
# import json
# hashed=hashlib.sha256()
# password=password.encode('ASCII')
#         hashed.update(password)
#         print(hashed.hexdigest())


from flask import Flask,jsonify,request,render_template,render_template_string
import os
import datetime

import rsa.key
app= Flask(__name__)
import pymongo
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
# from pymongo.server_api import ServerApi
# from cryptography.fernet import Fernet
import base64
import rsa
import binascii
from flask_cors import CORS
CORS(app, origins="http://localhost:5173")
load_dotenv()
# uri = "mongodb+srv://vasukotadiya224:ZnbujRS3Vm5sHJSz@cluster0.baqiyze.mongodb.net/oauth?retryWrites=true&w=majority&appName=Cluster0"
uri=os.getenv('MONGODB_URL')

client = MongoClient(uri)
db=client[os.getenv('DB_NAME')]
collectionandroid=db[os.getenv('COLLECTION_NAME1')]
collectiontoken=db[os.getenv('COLLECTION_NAME2')]
collectionutoken=db[os.getenv('COLLECTION_NAME3')]

# privateKey=rsa.key.PrivateKey(os.getenv('PRIVATE_KEY_N'),os.getenv('PRIVATE_KEY_P'),os.getenv('PRIVATE_KEY_K'),os.getenv('PRIVATE_KEY_E'),os.getenv('PRIVATE_KEY_L'))
# publicKey=rsa.key.PublicKey(os.getenv('PUBLIC_KEY_N'),os.getenv('PUBLIC_KEY_P'))

private_key_pem=base64.b64decode(os.getenv('PRIVATE_KEY')).decode('utf-8')
public_key_pem=base64.b64decode(os.getenv('PUBLIC_KEY')).decode('utf-8')


privateKey=rsa.PrivateKey.load_pkcs1(private_key_pem.encode('utf-8'))
publicKey=rsa.key.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))


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
        db.create_collection("Atoken", validator={"$jsonSchema": schema2})
        print("Collection created with schema validation")
    except pymongo.errors.CollectionInvalid:
        print("Collection already exists")
        
    try:
        db.create_collection("Utoken", validator={"$jsonSchema": schema2})
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


@app.route('/')
def default():
    return render_template_string("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Welcome To Weboauth API</title></head><body><h3>Please Make request of server side</h3></body></html>""")
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
            appid=data.get('_id')
            token=(appid+"$"+time+"$"+data.get("redirect_url")).encode('ASCII')
            cipher = rsa.encrypt(token, publicKey)
            base64Text = base64.urlsafe_b64encode(cipher).decode()
            data['accessToken']=base64Text
            print(data)
            try:
                collectiontoken.insert_one({'token':base64Text})
                return jsonify(data)
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


def genrateAccessToken(data):
    time=str(int(datetime.datetime.utcnow().timestamp())+30000)
    appid=data.get('_id')
    token=(appid+"$"+time+"$"+data.get("redirect_url")).encode('ASCII')
    cipher = rsa.encrypt(token, publicKey)
    base64Text = base64.urlsafe_b64encode(cipher).decode()
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
@app.route('/validatetoken',methods=['POST'])
def validateToken():
    # try:
    #     x=collectiontoken.find({'token':accessToken})
    #     if(x==None):
    #         return "Invalid Token"
    # except pymongo.errors.PyMongoError as e:
    #     print("Document retrieval failed:", e)
    #     return e
    # accessToken=request.headers.get('Access-Token')
    token=request.json
    
    accessToken=token.get('accesstoken')
    print(accessToken)
    if accessToken is None:
        return jsonify({"message":"ACCESS TOKEN NOT FOUND"})
    
    # accessToken=request.args.get('accesstoken')
    try:
        text = rsa.decrypt(base64.urlsafe_b64decode(accessToken.encode()), privateKey)
    except rsa.pkcs1.DecryptionError as e:
        print("invalid token decryption failed")
        return jsonify({"message":"INVALID TOKEN"})

    except binascii.Error as e1:
        return jsonify({"message":"INVALID TOKEN"})
    print(text.decode())
    token=text.decode()
    token=token.split("$")
    appid,time,redirect=token[0],token[1],token[2]
    time=int(time)
    if(datetime.datetime.utcnow().timestamp()>time):
        return jsonify({"message":"Timed Out"})
    return jsonify({'time':time,'redirect':redirect}),200


@app.route('/getusertoken',methods=['GET'])
def get_udata():
    uid=request.headers.get('userid')
    # genrateAccessToken(data)
    time=str(int(datetime.datetime.utcnow().timestamp())+30000)
    token=(time+"$"+uid).encode('ASCII')
    cipher = rsa.encrypt(token, publicKey)
    base64Text = base64.urlsafe_b64encode(cipher).decode()
    data={"userToken":base64Text}
    print(data)
    try:
        collectiontoken.insert_one({'token':base64Text})
        return jsonify(data)
    except pymongo.errors.WriteError as e:
        print("Document insertion failed:", e)
        return False
    # return data

@app.route('/validateutoken',methods=['GET'])
def validateUToken():
    # try:
    #     x=collectiontoken.find({'token':accessToken})
    #     if(x==None):
    #         return "Invalid Token"
    # except pymongo.errors.PyMongoError as e:
    #     print("Document retrieval failed:", e)
    #     return e
    # accessToken=request.headers.get('Access-Token')
    token=request.json
    
    userToken=token.get('usertoken')
    print(userToken)
    if userToken is None:
        return jsonify({"message":"USER TOKEN NOT FOUND"})
    
    # accessToken=request.args.get('accesstoken')
    try:
        text = rsa.decrypt(base64.urlsafe_b64decode(userToken.encode()), privateKey)
    except rsa.pkcs1.DecryptionError as e:
        print("invalid token decryption failed")
        return jsonify({"message":"INVALID TOKEN"})

    except binascii.Error as e1:
        return jsonify({"message":"INVALID TOKEN"})
    print(text.decode())
    token=text.decode()
    token=token.split("$")
    time,uid=token[0],token[1]
    time=int(time)
    if(datetime.datetime.utcnow().timestamp()>time):
        return jsonify({"message":"Timed Out"})
    return jsonify({'time':time,'uid':uid}),200



if __name__ == '__main__':
    app.run()
