# In one terminal, run:
dotnet run

# In your browser or via curl:

# 1) Insecure route (HTTP):
curl -i http://localhost:8080/
# → 401 or prompt, then try:
curl -i -H "Authorization: Basic $(echo -n 'john:password'| base64)" \
     http://localhost:8080/

# 2) Secure route (HTTPS):
curl -k -i https://localhost:8443/securelogin
# → 401 or prompt, then try:
curl -k -i -H "Authorization: Basic $(echo -n 'admin:password'| base64)" \
     https://localhost:8443/securelogin
