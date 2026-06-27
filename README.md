# Kefu Support Chat

Customer support chat system with:

- Customer chat page protected by conversation keys
- Admin backend login
- Admin-generated conversation keys
- WebSocket real-time messaging
- Telegram relay for customer messages and admin replies
- Image messages with 7-day local upload cleanup
- SQLite message storage

## Environment

Copy `.env.example` to `.env` and set real values:

```env
TELEGRAM_TOKEN=replace-with-telegram-bot-token
ADMIN_CHAT_ID=replace-with-telegram-chat-id
ADMIN_USERNAME=replace-with-admin-username
ADMIN_PASSWORD=replace-with-admin-password
```

Never commit `.env` or real tokens.

## Run Locally

```bash
npm install
npm start
```

The app listens on port `19999`.

## Docker

```bash
docker build -t kefu-support .
docker run -d \
  --name kefu-support \
  --restart always \
  -p 19999:19999 \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  kefu-support
```

## Pages

- Customer chat: `/`
- Admin backend: `/admin.html`
