# 1. Health check
curl http://localhost:3000/health

# 2. Register new user
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo@example.com\",\"password\":\"mypassword123\"}"

# 3. Copy the token from above, then login (should work)
curl -X POST http://localhost:3000/api/users/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo@example.com\",\"password\":\"mypassword123\"}"

# 4. Get your profile (replace TOKEN with your actual token)
curl http://localhost:3000/api/users/me \
  -H "Authorization: Bearer TOKEN"

# 5. Create a test file
echo "This is my awesome test file!" > myfile.txt

# 6. Upload the file (replace TOKEN)
curl -X POST http://localhost:3000/api/files \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@myfile.txt"

# 7. List all your files (replace TOKEN)
curl http://localhost:3000/api/files \
  -H "Authorization: Bearer TOKEN"

# 8. Get audit logs (replace TOKEN)
curl http://localhost:3000/api/audit/logs \
  -H "Authorization: Bearer TOKEN"

# 9. Check the storage directory
ls -la storage/
