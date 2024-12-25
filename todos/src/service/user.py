import random
import time
import bcrypt
from datetime import datetime, timedelta
from jose import jwt

class UserService:
    encoding: str = 'UTF-8'
    secret_key: str = '98d1237d3320688915219cd08a2833bc31783ea7b59da8b7a5edf815f8f4e110'
    jwt_algorithm: str = "HS256"

    def hash_password(self, plain_password: str) -> str:
        hash_password: bytes = bcrypt.hashpw(
            plain_password.encode(self.encoding),
            salt=bcrypt.gensalt()
        )
        return hash_password.decode(self.encoding)


    def verify_password(self,
                        plain_password: str,
                        hashed_password: str
    ) -> bool:
        # try/except
        return bcrypt.checkpw(
            plain_password.encode(self.encoding),
            hashed_password.encode(self.encoding)
        )

    def create_jwt(self, username: dict) -> str:
        return jwt.encode(
            {
                "sub": username,    # unique id
                "exp": datetime.now() + timedelta(days=1)
            },
            self.secret_key,
            algorithm=self.jwt_algorithm,
        )

    def decode_jwt(self, access_token: str):
        payload: dict = jwt.decode(
            access_token,
            self.secret_key,
            algorithms=[self.jwt_algorithm]
        )

        return payload['sub']

    @staticmethod
    def create_otp() -> int:
        return random.randint(1000, 9999)

    @staticmethod
    def send_email_to_user(email: str) -> None:
        time.sleep(10)
        print(f'Send email to {email}!')