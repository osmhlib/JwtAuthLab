using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

//один тестовий користувач і тимчасовий ключ підпису.
const string username = "admin";
const string password = "123456";
const string issuer = "JwtAuthLab";
var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

app.MapGet("/", () => Results.Content("""
<!DOCTYPE html>
<html lang="uk">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JWT Authentication Lab</title>
  <style>
    body { font: 16px Arial, sans-serif; background: #f3f5f9; margin: 0; padding: 40px 15px; }
    main { max-width: 520px; margin: auto; background: white; padding: 28px; border-radius: 14px;
           box-shadow: 0 5px 24px #0001; }
    h1 { font-size: 24px; margin-top: 0; }
    label { display: block; margin: 14px 0 5px; font-weight: bold; }
    input, textarea { width: 100%; box-sizing: border-box; padding: 11px; border: 1px solid #bac2ce;
                      border-radius: 7px; font: inherit; }
    textarea { height: 115px; resize: vertical; font-size: 12px; overflow-wrap: anywhere; }
    button { cursor: pointer; border: 0; border-radius: 7px; padding: 11px 14px; margin: 12px 8px 0 0;
             background: #285cc5; color: white; font-weight: bold; }
    button.secondary { background: #555d6b; }
    #result { margin-top: 18px; padding: 13px; border-radius: 7px; background: #f0f3f7;
              white-space: pre-wrap; overflow-wrap: anywhere; }
    small { color: #555d6b; }
  </style>
</head>
<body>
  <main>
    <h1>JWT Authentication Lab</h1>
    <small>Тестовий користувач: admin / 123456. Токен дійсний 2 хвилини.</small>
    <form id="loginForm">
      <label for="username">Логін</label>
      <input id="username" value="admin" required>
      <label for="password">Пароль</label>
      <input id="password" type="password" value="123456" required>
      <button type="submit">Увійти й отримати JWT</button>
    </form>
    <label for="token">JWT-токен (можна редагувати для перевірки помилки)</label>
    <textarea id="token" placeholder="Токен з’явиться після входу"></textarea>
    <button id="verify" type="button">Перевірити токен</button>
    <button id="damage" class="secondary" type="button">Пошкодити токен</button>
    <div id="result" aria-live="polite">Результат з’явиться тут.</div>
  </main>
<script>
  const result = document.getElementById('result');
  const token = document.getElementById('token');
  document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const response = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    });
    const data = await response.json();
    if (!response.ok) { result.textContent = data.message; return; }
    token.value = data.token;
    result.textContent = 'JWT створено! Діє до: ' + new Date(data.expiresAt).toLocaleTimeString();
  });
  document.getElementById('verify').addEventListener('click', async () => {
    const response = await fetch('/profile', {
      headers: {'Authorization': 'Bearer ' + token.value.trim()}
    });
    const data = await response.json();
    result.textContent = response.status + ': ' + data.message;
  });
  document.getElementById('damage').addEventListener('click', () => {
    const t = token.value.trim();
    if (!t) { result.textContent = 'Спочатку отримай токен.'; return; }
    const parts = t.split('.');
    if (parts.length !== 3 || !parts[2]) { result.textContent = 'Немає підпису для зміни.'; return; }
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    token.value = parts.join('.');
    result.textContent = 'Підпис токена змінено. Натисни «Перевірити токен».';
  });
</script>
</body>
</html>
""", "text/html; charset=utf-8"));

app.MapPost("/login", (LoginRequest data) =>
{
    if (data.Username != username || data.Password != password)
        return Results.Json(new { message = "Неправильний логін або пароль" }, statusCode: 401);

    var expires = DateTime.UtcNow.AddMinutes(2);
    var jwt = new JwtSecurityToken(
        issuer: issuer,
        audience: issuer,
        claims: new[] { new Claim(JwtRegisteredClaimNames.Sub, username) },
        expires: expires,
        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

    return Results.Ok(new { token = handler.WriteToken(jwt), expiresAt = expires });
});

app.MapGet("/profile", (HttpRequest request) =>
{
    var authorization = request.Headers.Authorization.ToString();
    if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        return Results.Json(new { message = "Токен відсутній" }, statusCode: 401);

    try
    {
        var principal = handler.ValidateToken(authorization[7..].Trim(), new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = issuer,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.Zero
        }, out _);

        var name = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        return Results.Ok(new { message = $"Доступ дозволено! Користувач: {name}" });
    }
    catch (SecurityTokenExpiredException)
    {
        return Results.Json(new { message = "Термін дії токена закінчився" }, statusCode: 401);
    }
    catch (SecurityTokenException)
    {
        return Results.Json(new { message = "Недійсний токен" }, statusCode: 401);
    }
    catch (ArgumentException)
    {
        return Results.Json(new { message = "Некоректний формат токена" }, statusCode: 401);
    }
});

app.Run();

record LoginRequest(string Username, string Password);
