# Microservices API System

A production-ready microservices architecture built with Go, featuring user management, file storage, and comprehensive audit logging.

## Features

- 🔐 **Security Controller**: JWT-based authentication with bcrypt password hashing
- 👤 **User API**: User registration, login, and profile management
- 📁 **File API**: Secure file upload, download, and listing
- 📊 **Audit API**: Comprehensive activity logging with metadata
- 🚀 **High Performance**: Built with Go for speed and efficiency
- 🔄 **Load Balancer Ready**: Stateless design for horizontal scaling
- 🐳 **Docker Support**: Full containerization with Docker Compose
- 🛡️ **Production Ready**: Graceful shutdown, CORS, timeouts, and more

## Architecture

```
Client → Load Balancer (Nginx) → Node Instances → APIs → Database
                                      ├── User API
                                      ├── File API
                                      └── Audit API
                                           ↓
                                      Security Controller
```

## Quick Start

### Prerequisites

- Go 1.21 or higher


### Local Development

1. **Clone and setup**
```bash
git clone <your-repo>
cd microservices
```

2. **Install dependencies**
```bash
make deps
# or
go mod download
```

3. **Run the server**
```bash
make run
# or
go run main.go
```

Server starts on `http://localhost:8080`

### Docker Deployment

1. **Build and run**
```bash
make docker-run
# or
docker-compose up -d
```

2. **View logs**
```bash
make docker-logs
# or
docker-compose logs -f
```

3. **Stop services**
```bash
make docker-stop
# or
docker-compose down
```

## API Endpoints

### Authentication

#### Register User
```bash
curl -X POST http://localhost:8080/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

Response:
```json
{
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "created": "2025-10-15T10:30:00Z"
  },
  "token": "jwt-token-here"
}
```

#### Login
```bash
curl -X POST http://localhost:8080/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### User Management

#### Get Profile
```bash
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### File Management

#### Upload File
```bash
curl -X POST http://localhost:8080/api/files \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@/path/to/your/file.pdf"
```

Response:
```json
{
  "id": "file-uuid",
  "user_id": "user-uuid",
  "name": "file.pdf",
  "size": 1024000,
  "mime_type": "application/pdf",
  "created": "2025-10-15T10:35:00Z"
}
```

#### List Files
```bash
curl http://localhost:8080/api/files \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Download File
```bash
curl http://localhost:8080/api/files/{fileID} \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -O
```

### Audit Logs

#### Get User Audit Logs
```bash
curl http://localhost:8080/api/audit/logs \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Response:
```json
[
  {
    "id": "log-uuid",
    "user_id": "user-uuid",
    "action": "FILE_UPLOAD",
    "resource": "file-uuid",
    "ip": "192.168.1.1",
    "user_agent": "curl/7.68.0",
    "metadata": {
      "filename": "document.pdf",
      "size": 1024000
    },
    "timestamp": "2025-10-15T10:35:00Z"
  }
]
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `JWT_SECRET` | (required) | JWT signing secret |
| `STORAGE_PATH` | `./storage` | File storage directory |

### Production Setup

Create a `.env` file:
```bash
PORT=8080
JWT_SECRET=your-very-secure-random-secret-min-32-chars
STORAGE_PATH=/var/app/storage
```

## Architecture Components

### Security Controller
- JWT token generation and validation
- Password hashing with bcrypt (cost factor: 14)
- Authorization checks (extensible to RBAC)

### User API
- User registration with duplicate email check
- Secure login with password verification
- Profile management
- Full audit trail

### File API
- Multipart file upload (max 50MB)
- File listing with user isolation
- Secure file download with authorization
- File metadata tracking
- Storage on disk (easily replaceable with S3)

### Audit API
- Asynchronous log processing
- Captures: user, action, resource, IP, user agent, metadata
- Buffered channel for performance (1000 logs)
- Queryable audit trail per user

### Database Layer
- Clean abstraction for easy replacement
- In-memory storage for demo (replace with DynamoDB/PostgreSQL)
- Thread-safe with RWMutex
- CRUD operations for all entities

## Performance Features

- **Goroutines**: Async audit logging doesn't block requests
- **Connection Pooling**: HTTP/2 support with keep-alive
- **Timeouts**: Request, read, write, and idle timeouts
- **Graceful Shutdown**: 30-second grace period for in-flight requests
- **Rate Limiting**: Ready for middleware integration
- **CORS**: Configured for cross-origin requests

## Scaling

### Horizontal Scaling
```yaml
# docker-compose.yml
services:
  app1:
    build: .
    ports: ["8081:8080"]
  
  app2:
    build: .
    ports: ["8082:8080"]
  
  app3:
    build: .
    ports: ["8083:8080"]
  
  nginx:
    # Load balances across all instances
```

## Monitoring

### Health Check
```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-15T10:30:00Z"
}
```

### Metrics
```go
// Add to main.go
import "github.com/prometheus/client_golang/prometheus/promhttp"

r.Handle("/metrics", promhttp.Handler())
```
## License

MIT License - feel free to use this in your projects!# microservices
