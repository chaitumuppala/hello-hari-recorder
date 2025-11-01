# 🛡️ Indian Scam Detection PWA

A Progressive Web Application (PWA) for real-time detection and prevention of phone scams targeting Indian users. Uses advanced speech recognition and machine learning to identify potential scam calls in multiple Indian languages.

## 📋 Project Description

This application helps protect users from phone scams by:
- **Real-time audio analysis** of incoming calls
- **Multi-language support** for Indian languages (Hindi, Tamil, Telugu, Bengali, etc.)
- **AI-powered scam detection** using IndicConformer models
- **Offline capability** through PWA features
- **Privacy-first design** with local processing when possible

## 🚀 Tech Stack

### Frontend
- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **PWA** - Progressive Web App features
- **Web Audio API** - Real-time audio processing
- **IndexedDB** - Local data storage

### Backend
- **FastAPI** - Modern Python web framework
- **Python 3.10+** - Backend language
- **IndicConformer** - Speech recognition for Indian languages
- **PyTorch** - Deep learning framework
- **SQLAlchemy** - Database ORM
- **PostgreSQL** - Production database

### ML/AI Models
- **IndicConformer** - Indian language speech recognition
- **Custom NLP models** - Scam pattern detection
- **ONNX Runtime** - Model inference optimization

## 🛠️ Setup Instructions

### Prerequisites
- Node.js 18+ and npm/yarn
- Python 3.10+
- PostgreSQL (for production)
- Git

### Backend Setup

1. **Navigate to backend directory:**
   ```powershell
   cd backend
   ```

2. **Create virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   Create a `.env` file in the `backend` directory:
   ```env
   DATABASE_URL=postgresql://user:password@localhost/scam_detector
   SECRET_KEY=your-secret-key-here
   MODEL_PATH=./models
   ENVIRONMENT=development
   ```

5. **Run database migrations:**
   ```powershell
   alembic upgrade head
   ```

6. **Start the backend server:**
   ```powershell
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Frontend Setup

1. **Navigate to frontend directory:**
   ```powershell
   cd frontend
   ```

2. **Install dependencies:**
   ```powershell
   npm install
   # or
   yarn install
   ```

3. **Set up environment variables:**
   Create a `.env` file in the `frontend` directory:
   ```env
   VITE_API_URL=http://localhost:8000
   VITE_WS_URL=ws://localhost:8000/ws
   ```

4. **Start the development server:**
   ```powershell
   npm run dev
   # or
   yarn dev
   ```

5. **Access the application:**
   Open your browser and navigate to `http://localhost:5173`

### Download ML Models

1. **Navigate to scripts directory:**
   ```powershell
   cd scripts/setup
   ```

2. **Run model download script:**
   ```powershell
   python download_models.py
   ```

## 🧪 Testing Instructions

### Backend Tests

```powershell
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_api.py

# Run with verbose output
pytest -v
```

### Frontend Tests

```powershell
cd frontend

# Run all tests
npm test
# or
yarn test

# Run with coverage
npm run test:coverage

# Run in watch mode
npm run test:watch

# Run e2e tests
npm run test:e2e
```

## 📱 Local Development on Mobile Phone

### Method 1: Using ngrok (Recommended)

1. **Install ngrok:**
   ```powershell
   # Download from https://ngrok.com/download
   # Or use Chocolatey
   choco install ngrok
   ```

2. **Start your backend server:**
   ```powershell
   cd backend
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

3. **Start your frontend server:**
   ```powershell
   cd frontend
   npm run dev -- --host 0.0.0.0
   ```

4. **Expose frontend with ngrok:**
   ```powershell
   ngrok http 5173
   ```

5. **Access on mobile:**
   - Use the ngrok URL (e.g., `https://xxxx-xx-xx-xx-xx.ngrok.io`) on your mobile browser
   - Update frontend `.env` with the backend ngrok URL if needed

### Method 2: Local Network Access

1. **Find your local IP address:**
   ```powershell
   ipconfig
   # Look for IPv4 Address (e.g., 192.168.1.100)
   ```

2. **Start backend with host binding:**
   ```powershell
   cd backend
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

3. **Start frontend with host binding:**
   ```powershell
   cd frontend
   npm run dev -- --host 0.0.0.0
   ```

4. **Update frontend environment variables:**
   ```env
   VITE_API_URL=http://YOUR_LOCAL_IP:8000
   VITE_WS_URL=ws://YOUR_LOCAL_IP:8000/ws
   ```

5. **Access on mobile:**
   - Ensure both devices are on the same WiFi network
   - Open `http://YOUR_LOCAL_IP:5173` on your mobile browser

6. **Enable PWA features:**
   - For HTTPS (required for PWA), use ngrok or set up local SSL certificates
   - Install the PWA from browser menu (Add to Home Screen)

### Method 3: Using Cloudflare Tunnel (Zero Config)

1. **Install cloudflared:**
   ```powershell
   # Download from https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/
   ```

2. **Start tunnel:**
   ```powershell
   cloudflared tunnel --url http://localhost:5173
   ```

3. **Access the generated URL on your mobile device**

## 🔐 Security Notes

- Never commit `.env` files or API keys
- Use HTTPS in production
- Models should be downloaded separately and not committed to Git
- Implement rate limiting on API endpoints
- Sanitize all user inputs

## 📚 Documentation

- API Documentation: `docs/api/`
- Architecture: `docs/architecture/`
- Deployment Guide: `docs/deployment/`
- User Guide: `docs/user-guide/`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- IndicConformer team for Indian language models
- FastAPI community
- React and Vite teams
- All contributors and testers

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Made with ❤️ for a safer digital India**