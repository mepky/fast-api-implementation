from sqlalchemy import Column, Integer, String
from database import Base
  
class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150))
    email = Column(String(150), unique=True)
    password = Column(String(150))
    bio = Column(String(1000))
    mobile= Column(String(15))
  
    def __repr__(self):
        return '<User %r>' % (self.id) 
    

class userToken(Base):
    __tablename__ = 'userToken'
    id = Column(Integer, primary_key=True)
    username = Column(String(150))
    email = Column(String(150), unique=True)
    token = Column(String(1000))
    def __repr__(self):
        return '<User %r>' % (self.email) 
    
