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
- Docker & Docker Compose (optional)
- Make (optional)

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

## Project Structure

```
.
├── main.go              # Main application entry point
├── go.mod               # Go dependencies
├── go.sum               # Dependency checksums
├── Dockerfile           # Container build instructions
├── docker-compose.yml   # Multi-container setup
├── nginx.conf           # Load balancer configuration
├── Makefile            # Build automation
├── README.md           # This file
└── storage/            # File storage directory
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

### AWS Deployment

1. **Replace in-memory DB with DynamoDB**:
```go
// Add AWS SDK
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Initialize DynamoDB client
cfg, _ := config.LoadDefaultConfig(context.TODO())
dynamoClient := dynamodb.NewFromConfig(cfg)
```

2. **Replace local storage with S3**:
```go
import "github.com/aws/aws-sdk-go-v2/service/s3"

s3Client := s3.NewFromConfig(cfg)
// Use PutObject and GetObject instead of file system
```

3. **Deploy to ECS/EKS**:
- Build Docker image
- Push to ECR
- Create ECS task definition
- Set up Application Load Balancer
- Configure auto-scaling

## Security Best Practices

✅ **Implemented:**
- JWT token expiration (24 hours)
- Bcrypt password hashing (cost 14)
- Authorization middleware
- CORS configuration
- Request size limits
- Timeout protection
- Input validation

⚠️ **Production Recommendations:**
- Use HTTPS/TLS in production
- Implement rate limiting per IP/user
- Add request signing for API-to-API calls
- Enable audit log encryption at rest
- Set up log aggregation (ELK, CloudWatch)
- Implement token refresh mechanism
- Add API key management for service accounts
- Use secrets manager for JWT_SECRET
- Enable database encryption
- Implement OWASP security headers

## Testing

```bash
# Run all tests
make test

# Run with coverage
go test -cover ./...

# Run benchmarks
make benchmark

# Load testing with Apache Bench
ab -n 1000 -c 10 http://localhost:8080/health
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

### Metrics (Add Prometheus)
```go
// Add to main.go
import "github.com/prometheus/client_golang/prometheus/promhttp"

r.Handle("/metrics", promhttp.Handler())
```

## Troubleshooting

### Port already in use
```bash
# Kill process on port 8080
lsof -ti:8080 | xargs kill -9
```

### Storage permission errors
```bash
chmod -R 755 ./storage
```

### Docker build fails
```bash
# Clean Docker cache
docker system prune -a
docker-compose build --no-cache
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - feel free to use this in your projects!# microservices
