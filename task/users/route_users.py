from models import Users
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi import responses
from fastapi import status
from fastapi.templating import Jinja2Templates
from models import Users
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from users import UserCreateForm


templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=False)


@router.get("/register/")
def register(request: Request):
    return templates.TemplateResponse("templates/register.html", {"request": request})


@router.post("/register/")
async def register(request: Request):
    form = UserCreateForm(request)
    await form.load_data()
    if await form.is_valid():
        user = Users(
            username=form.username, email=form.email, password=form.password
        )
        try:
            user = Users(user=user)
            return responses.RedirectResponse(
                "/?msg=Successfully-Registered", status_code=status.HTTP_302_FOUND
            )  # default is post request, to use get request added status code 302
        except IntegrityError:
            form.__dict__.get("errors").append("Duplicate username or email")
            return templates.TemplateResponse("register.html", form.__dict__)
    return templates.TemplateResponse("register.html", form.__dict__)