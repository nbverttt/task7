<?php

/**
 * Задание 7 - Исправлены уязвимости:
 * - XSS (htmlspecialchars)
 * - SQL Injection (PDO prepared statements)
 * - CSRF (токен)
 * - Information Disclosure (отключены ошибки)
 * - Session security (httponly, samesite)
 */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/error.log');

header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Настройки БД
$db_user = 'u82591';
$db_pass = '2762718';
$db_name = 'u82591';

// Запуск сессии с безопасными настройками
$session_started = false;
if (!empty($_COOKIE[session_name()])) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => false,
        'cookie_samesite' => 'Lax',
    ]);
    $session_started = true;
}

// Генерация CSRF-токена
if ($session_started && empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Обработка выхода
if (isset($_GET['logout']) && $session_started) {
    // Удаляем сессию
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header('Location: index.php');
    exit();
}

// Если пользователь уже авторизован
if ($session_started && !empty($_SESSION['login'])) {
    header('Location: index.php');
    exit();
}

// Обработка GET запроса - показ формы логина
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    // Запускаем сессию для нового пользователя
    if (!$session_started) {
        session_start([
            'cookie_httponly' => true,
            'cookie_secure' => false,
            'cookie_samesite' => 'Lax',
        ]);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        .login-container h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-weight: 600; margin-bottom: 8px; color: #333; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 5px rgba(102, 126, 234, 0.3);
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .error-message {
            background-color: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #667eea; text-decoration: none; }
        .back-link a:hover { text-decoration: underline; }
        .admin-link { text-align: center; margin-top: 15px; }
        .admin-link a { color: #e74c3c; text-decoration: none; }
        .admin-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Вход в систему</h1>
        
        <?php if (isset($_GET['error']) && $_GET['error'] == 'wrong'): ?>
            <div class="error-message">Неверный логин или пароль.</div>
        <?php endif; ?>
        
        <form action="login.php" method="POST">
            <!-- CSRF-токен -->
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            
            <div class="form-group">
                <label for="login">Логин</label>
                <input type="text" id="login" name="login" required placeholder="Введите логин"
                       maxlength="50"
                       value="<?= htmlspecialchars($_POST['login'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
            </div>
            
            <div class="form-group">
                <label for="pass">Пароль</label>
                <input type="password" id="pass" name="pass" required placeholder="Введите пароль" maxlength="50">
            </div>
            
            <button type="submit">Войти</button>
        </form>
        
        <div class="back-link">
            <a href="index.php">Вернуться к форме</a>
        </div>
        
        <div class="admin-link">
            <a href="admin.php">Войти как администратор</a>
        </div>
    </div>
</body>
</html>
<?php
    exit();
}

// Обработка POST запроса - проверка логина и пароля
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    
    // Запускаем сессию если ещё не запущена
    if (!$session_started) {
        session_start([
            'cookie_httponly' => true,
            'cookie_secure' => false,
            'cookie_samesite' => 'Lax',
        ]);
    }
    
    // Проверка CSRF-токена
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Ошибка проверки CSRF-токена. Пожалуйста, обновите страницу и попробуйте снова.');
    }
    
    $login = trim($_POST['login'] ?? '');
    $pass = trim($_POST['pass'] ?? '');
    
    if (empty($login) || empty($pass)) {
        header('Location: login.php?error=wrong');
        exit();
    }
    
    try {
        $db = new PDO("mysql:host=localhost;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        
        // Ищем пользователя (только по логину)
        $stmt = $db->prepare("SELECT id, login, password_hash FROM application WHERE login = ? LIMIT 1");
        $stmt->execute([$login]);
        $user = $stmt->fetch();
        
        if ($user && $user['password_hash'] === md5($pass)) {
            // Успешная авторизация
            // Регенерируем ID сессии для защиты от фиксации сессии
            session_regenerate_id(true);
            
            $_SESSION['login'] = $user['login'];
            $_SESSION['uid'] = (int)$user['id'];
            
            // Обновляем CSRF-токен после входа
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            
            // Удаляем куки с данными формы
            $cookie_fields = ['fio_value', 'phone_value', 'email_value', 'birth_date_value', 
                            'gender_value', 'biography_value', 'contract_accepted_value', 'languages_value'];
            foreach ($cookie_fields as $cookie) {
                setcookie($cookie, '', time() - 3600, '/', '', false, true);
            }
            
            // Перенаправление на главную
            header('Location: index.php');
            exit();
        } else {
            // Защита от перебора паролей: логируем неудачную попытку
            error_log("Неудачная попытка входа с логином: " . substr($login, 0, 20));
            
            // Задержка для защиты от брутфорса
            sleep(1);
            
            header('Location: login.php?error=wrong');
            exit();
        }
        
    } catch (PDOException $e) {
        error_log('Ошибка БД при авторизации: ' . $e->getMessage());
        die('Ошибка сервера. Попробуйте позже.');
    }
}
