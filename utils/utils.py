from models.models import User

async def create_test_user():
    user = User(username="testuser", password="hashedpassword")
    await user.insert()
