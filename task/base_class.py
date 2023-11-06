
from typing import Any
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import as_declarative

from fastapi import APIRouter
from users import route_users  #new


api_router = APIRouter()
api_router.include_router(route_users.router, prefix="", tags=["users"])  #new
@as_declarative()
class Base:
    id: Any
    __name__: str

    #to generate tablename from classname
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()