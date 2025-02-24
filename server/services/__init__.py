from server.core.config import conf
from server.services.users_service import UsersManager
users_ = UsersManager(conf("databases", "users"))

from server.services.auth_service import AdminChallenge, UserChallenge, TokensManager
admin_challenge = AdminChallenge()
user_challenge = UserChallenge()
tokens_ = TokensManager(conf("databases", "tokens"))

from server.services.messages_service import MessagesManager
messages_ = MessagesManager(conf("databases", "messages"))