from typing import List
from typing import Optional
from fastapi import Request



class UserCreateForm:
    def __init__(self, request:Request) :
        self.request:Request = request
        self.errors:List=[]
        self.username:Optional[str]=None
        self.email:Optional[str]=None
        self.password:Optional[str]=None
        self.bio :Optional[str] = None
        self.mobile : Optional[str] = None


    async def load_data(self):
        form = await self.request.form()
        self.username = form.get("username")
        self.email = form.get("email")
        self.password = form.get("password")
        self.bio = form.get("bio")
        self.mobile = form.get("mobile")

        

    async def is_valid(self):
        if not self.username or not len(self.username)>3:
            self.errors.append("Username should be >3 Chars")

        if not self.email or not (self.email.__contains__("@")):
            self.errors.append("Email is required")

        if not self.password or not len(self.password)>=4:
            self.errors.append("Password must be > 4 chars")

        # if not self.mobile or not len(self.mobile)==10:
        #     self.errors.append("10 digits are expected in mobile number")

        if not self.errors:
            return True
        return False
    


class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.username = form.get(
            "email"
        )  # since outh works on username field we are considering email as username
        self.password = form.get("password")

    async def is_valid(self):
        if not self.username or not (self.username.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or not len(self.password) >= 4:
            self.errors.append("A valid password is required")
        if not self.errors:
            return True
        return False