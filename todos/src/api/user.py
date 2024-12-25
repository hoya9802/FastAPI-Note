from cache import redis_client
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from database.orm import User
from database.repository import UserRepository
from schema.request import CreateOTPRequest, LogInRequest, SignUpRequest, VerifyOTPRequest
from schema.response import JWTResponse, UserSchema
from security import get_access_token
from service.user import UserService


router = APIRouter(prefix='/users')


@router.post("/sign-up", status_code=201)
def user_sign_up_handler(
    request: SignUpRequest,
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends()
):
    # 1. request body(username, password)
    # 2. password -> hashing -> hashed password
    hashed_password: str = user_service.hash_password(
        plain_password=request.password
    )

    # 3. User(username, hased_password)
    user: User = User.create(
        username=request.username,
        hashed_password=hashed_password
    )

    # 4. user -> db save
    user: User = user_repo.save_user(user=user)

    # 5. return user(id, username)
    return UserSchema.from_orm(user)


@router.post('/log-in')
def user_log_in_handler(
    request: LogInRequest,
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends(),
):
    # 1. reqeust body(username, password)
    # 2. DB read user
    user: User | None = user_repo.get_user_by_username(
        username=request.username
    )

    if not user:
        raise HTTPException(status_code=404, detail="User Not Found")

    # 3. user.password, request.password -> bcrypt.checkpw
    verified: bool = user_service.verify_password(
        plain_password=request.password,
        hashed_password=user.password,
    )
    if not verified:
        raise HTTPException(status_code=401, detail='Not Authorized')

    # 4. create jwt
    access_token: str = user_service.create_jwt(username=user.username)

    # 5. return jwt
    return JWTResponse(access_token=access_token)


@router.post("/email/otp")
def create_otp_handler(
    request: CreateOTPRequest,
    _: str = Depends(get_access_token),
    user_service: UserService = Depends(),

):
    # 1. access_token
    # 2. request body(email)
    # 3. otp create(random 4 digit)
    otp: int = user_service.create_otp()

    # 4. redis otp(email, 1234, exp=3min)
    redis_client.set(request.email, otp)
    redis_client.expire(request.email, 3 * 60)

    # 5. send otp to email
    return {"otp": otp}


@router.post("/email/otp/verify")
def verify_otp_handler(
    request: VerifyOTPRequest,
    background_tasks: BackgroundTasks,
    access_token: str = Depends(get_access_token),
    user_service: UserService = Depends(),
    user_repo: UserRepository = Depends(),
):
    # 1. access_token
    # 2. request body(email, otp)

    otp: str | None = redis_client.get(request.email)
    if not otp:
        raise HTTPException(status_code=400, detail="Bad Request")

    if request.otp != int(otp):
        raise HTTPException(status_code=400, detail="Bad Request")

    # 3. request.otp == redis.get(email)

    username: str = user_service.decode_jwt(access_token=access_token)
    user: User | None = user_repo.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User Not Found")

    # send email to user
    background_tasks.add_task(
        user_service.send_email_to_user,
        email="admin@fastapi.com"
    )
    return UserSchema.from_orm(user)
