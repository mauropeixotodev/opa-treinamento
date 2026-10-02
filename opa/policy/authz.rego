package authz

# ---------------------------------------------------------------
# 1. Configuração (vem das variáveis de ambiente do container OPA)
# ---------------------------------------------------------------
config := {
	"tenant_id": opa.runtime().env.AZURE_TENANT_ID,
	"audience": opa.runtime().env.AZURE_AUDIENCE,
}

# Emissores aceitos: token v2.0 e token v1.0 do Microsoft Entra ID
emissores_validos := {
	sprintf("https://login.microsoftonline.com/%s/v2.0", [config.tenant_id]),
	sprintf("https://sts.windows.net/%s/", [config.tenant_id]),
}

# ---------------------------------------------------------------
# 2. Chaves públicas da Microsoft (JWKS) - cache de 1h
# ---------------------------------------------------------------
jwks := http.send({
	"method": "GET",
	"url": sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", [config.tenant_id]),
	"force_cache": true,
	"force_cache_duration_seconds": 3600,
}).raw_body

# ---------------------------------------------------------------
# 3. Extrai o token do header "Authorization: Bearer <token>"
# ---------------------------------------------------------------
token := t if {
	startswith(input.authorization, "Bearer ")
	t := substring(input.authorization, count("Bearer "), -1)
}

# ---------------------------------------------------------------
# 4. Valida assinatura, expiração e audience do token
# ---------------------------------------------------------------
claims := payload if {
	[valido, _, payload] := io.jwt.decode_verify(token, {
		"cert": jwks,
		"aud": config.audience,
	})
	valido
	payload.iss in emissores_validos
}

token_valido if claims

# ---------------------------------------------------------------
# 5. Roles: qual role cada rota exige	
#    Use o campo "Value" da App Role cadastrada no Entra ID
#    (diferencia maiúsculas/minúsculas)
# ---------------------------------------------------------------
permissoes := {
	"GET /produtos": "Produtos.Leitura",
	"POST /produtos": "Produtos.Escrever",
}

rota := sprintf("%s %s", [input.method, input.path])

role_exigida := permissoes[rota]

# Claim "roles" do token Microsoft (lista vazia se o token não tiver roles)
roles := object.get(claims, "roles", [])

# ---------------------------------------------------------------
# 6. Regra de autorização
# ---------------------------------------------------------------
default allow := false

allow if {
	token_valido
	role_exigida in roles
}

# ---------------------------------------------------------------
# 7. Motivo da negação (ajuda a debugar e a explicar no treinamento)
# ---------------------------------------------------------------
motivo := "token ausente ou sem prefixo Bearer" if not token

else := "token inválido (assinatura, expiração, audience ou emissor)" if not token_valido

else := sprintf("rota não mapeada: %s", [rota]) if not role_exigida

else := sprintf("role '%s' ausente no token. Roles recebidas: %v", [role_exigida, roles]) if not allow

else := "permitido"

usuario := object.get(claims, "preferred_username", object.get(claims, "appid", "desconhecido")) if token_valido
