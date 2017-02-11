from application import db
# from sqlalchemy.dialects.postgresql import JSON


from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Text
import datetime
from sqlalchemy.orm import relationship


class User(db):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Catalog(db):
    __tablename__ = 'catalog'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False, unique=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        items = db.session.query(Item).filter_by(catalog_id=self.id).all()
        return {
            'name': self.name,
            'id': self.id,
            'items': [i.serialize for i in items]
        }


class Item(db):
    __tablename__ = 'item'

    name = Column(String(80), nullable=False, unique=True)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    photo = Column(Text)
    price = Column(String(8))
    created = Column(DateTime, default=datetime.datetime.utcnow)
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    catalog = relationship(Catalog)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
        }


db.create_all()
