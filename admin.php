<?php

/**
 * Задание 7 - Админ-панель с защитой:
 * - HTTP Basic Auth (отдельная аутентификация)
 * - XSS (htmlspecialchars)
 * - SQL Injection (PDO prepared statements)
 * - CSRF (токен в формах)
 * - Information Disclosure (отключены ошибки)
 * - Session security
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

$db_user = 'u82591';
$db_pass = '2762718';
$db_name = 'u82591';

// Подключение к БД
try {
    $db = new PDO("mysql:host=localhost;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $e) {
    error_log('Ошибка подключения к БД: ' . $e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    die('Ошибка сервера. Попробуйте позже.');
}

// Проверка администратора в БД
$stmt = $db->prepare("SELECT id, login, password_hash FROM admins LIMIT 1");
$stmt->execute();
$admin = $stmt->fetch();

if (!$admin) {
    // Создаём администратора по умолчанию
    $default_login = 'admin';
    $default_password = 'admin123';
    $password_hash = md5($default_password);
    
    $stmt = $db->prepare("INSERT INTO admins (login, password_hash) VALUES (?, ?)");
    $stmt->execute([$default_login, $password_hash]);
    $admin = ['login' => $default_login, 'password_hash' => $password_hash];
}

// HTTP Basic Auth проверка
if (
    empty($_SERVER['PHP_AUTH_USER']) ||
    empty($_SERVER['PHP_AUTH_PW']) ||
    !hash_equals($admin['login'], $_SERVER['PHP_AUTH_USER']) ||
    !hash_equals($admin['password_hash'], md5($_SERVER['PHP_AUTH_PW']))
) {
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Basic realm="Admin panel"');
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>401</title></head><body>';
    echo '<h1>401 Требуется авторизация</h1>';
    echo '<p>Доступ запрещён. Введите логин и пароль администратора.</p>';
    echo '</body></html>';
    exit();
}

// Запуск сессии для CSRF-токена
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => false,
    'cookie_samesite' => 'Lax',
]);

if (empty($_SESSION['admin_csrf_token'])) {
    $_SESSION['admin_csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$message_type = '';

// Обработка удаления
if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    $id = (int)$_GET['id'];
    
    // Проверка CSRF для GET-запроса удаления (через токен в URL)
    if (empty($_GET['token']) || !hash_equals($_SESSION['admin_csrf_token'], $_GET['token'])) {
        $message = 'Ошибка проверки безопасности. Попробуйте снова.';
        $message_type = 'error';
    } else {
        try {
            $db->beginTransaction();
            
            // Удаляем связи с языками
            $stmt = $db->prepare("DELETE FROM application_languages WHERE application_id = ?");
            $stmt->execute([$id]);
            
            // Удаляем саму запись
            $stmt = $db->prepare("DELETE FROM application WHERE id = ?");
            $stmt->execute([$id]);
            
            $db->commit();
            $message = "Запись #" . $id . " успешно удалена.";
            $message_type = 'success';
        } catch (PDOException $e) {
            $db->rollBack();
            error_log('Ошибка удаления: ' . $e->getMessage());
            $message = 'Ошибка удаления. Попробуйте позже.';
            $message_type = 'error';
        }
    }
}

// Обработка редактирования (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_id'])) {
    
    // Проверка CSRF-токена
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['admin_csrf_token'], $_POST['csrf_token'])) {
        die('Ошибка проверки CSRF-токена. Обновите страницу.');
    }
    
    $id = (int)$_POST['edit_id'];
    $fio = trim($_POST['fio'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $birth_date = $_POST['birth_date'] ?? '';
    $gender = $_POST['gender'] ?? '';
    $biography = trim($_POST['biography'] ?? '');
    $contract_accepted = $_POST['contract_accepted'] ?? '0';
    $languages = $_POST['languages'] ?? [];
    
    // Валидация
    $errors = [];
    
    if (empty($fio)) $errors[] = 'ФИО обязательно';
    if (empty($phone)) $errors[] = 'Телефон обязателен';
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Email некорректен';
    if (empty($birth_date)) $errors[] = 'Дата рождения обязательна';
    if (!in_array($gender, ['male', 'female'])) $errors[] = 'Пол выбран некорректно';
    
    if (!empty($errors)) {
        $message = 'Ошибки: ' . implode('; ', $errors);
        $message_type = 'error';
    } else {
        try {
            $db->beginTransaction();
            
            // Обновление основных данных
            $stmt = $db->prepare("UPDATE application SET fio=?, phone=?, email=?, birth_date=?, gender=?, biography=?, contract_accepted=? WHERE id=?");
            $stmt->execute([$fio, $phone, $email, $birth_date, $gender, $biography, $contract_accepted, $id]);
            
            // Обновление языков
            $stmt = $db->prepare("DELETE FROM application_languages WHERE application_id = ?");
            $stmt->execute([$id]);
            
            if (!empty($languages)) {
                $allowed_languages = ['Pascal', 'C', 'C++', 'JavaScript', 'PHP', 'Python', 
                                     'Java', 'Haskell', 'Clojure', 'Prolog', 'Scala', 'Go'];
                
                foreach ($languages as $lang) {
                    if (!in_array($lang, $allowed_languages, true)) {
                        continue; // Пропускаем неразрешённые языки
                    }
                    
                    $stmt_lang = $db->prepare("SELECT id FROM programming_languages WHERE name = ?");
                    $stmt_lang->execute([$lang]);
                    $lang_id = $stmt_lang->fetchColumn();
                    
                    if ($lang_id) {
                        $stmt_link = $db->prepare("INSERT INTO application_languages (application_id, language_id) VALUES (?, ?)");
                        $stmt_link->execute([$id, $lang_id]);
                    }
                }
            }
            
            $db->commit();
            $message = "Запись #" . $id . " успешно обновлена.";
            $message_type = 'success';
            
            // Обновляем CSRF-токен
            $_SESSION['admin_csrf_token'] = bin2hex(random_bytes(32));
            
        } catch (PDOException $e) {
            $db->rollBack();
            error_log('Ошибка обновления: ' . $e->getMessage());
            $message = 'Ошибка обновления. Попробуйте позже.';
            $message_type = 'error';
        }
    }
}

// Загрузка данных для отображения
$stmt = $db->query("
    SELECT a.*, GROUP_CONCAT(pl.name ORDER BY pl.name SEPARATOR ', ') as languages_list
    FROM application a
    LEFT JOIN application_languages al ON a.id = al.application_id
    LEFT JOIN programming_languages pl ON al.language_id = pl.id
    GROUP BY a.id
    ORDER BY a.id DESC
");
$applications = $stmt->fetchAll();

// Статистика
$stmt_stats = $db->query("
    SELECT pl.name, COUNT(al.application_id) as count
    FROM programming_languages pl
    LEFT JOIN application_languages al ON pl.id = al.language_id
    GROUP BY pl.id, pl.name
    ORDER BY count DESC, pl.name ASC
");
$stats = $stmt_stats->fetchAll();

$total_users = $db->query("SELECT COUNT(*) FROM application")->fetchColumn();

// Режим редактирования
$edit_mode = false;
$edit_data = null;
if (isset($_GET['action']) && $_GET['action'] === 'edit' && isset($_GET['id'])) {
    $edit_id = (int)$_GET['id'];
    $stmt = $db->prepare("SELECT * FROM application WHERE id = ?");
    $stmt->execute([$edit_id]);
    $edit_data = $stmt->fetch();
    
    if ($edit_data) {
        $stmt_lang = $db->prepare("SELECT pl.name FROM application_languages al JOIN programming_languages pl ON al.language_id = pl.id WHERE al.application_id = ?");
        $stmt_lang->execute([$edit_id]);
        $edit_data['languages'] = $stmt_lang->fetchAll(PDO::FETCH_COLUMN);
        $edit_mode = true;
    }
}

$all_languages = $db->query("SELECT name FROM programming_languages ORDER BY id")->fetchAll(PDO::FETCH_COLUMN);

?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Админ-панель</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f0f2f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 24px; }
        .header .nav-links { display: flex; gap: 15px; }
        .header .nav-links a { color: white; text-decoration: none; }
        .header .nav-links a:hover { text-decoration: underline; }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .message.success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }
        .message.error { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
        .stats-panel {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card .number { font-size: 32px; font-weight: bold; color: #3498db; }
        .stat-card .label { color: #666; margin-top: 5px; font-size: 14px; }
        .panel {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .panel h2 {
            margin-bottom: 15px;
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; font-size: 14px; }
        th { background: #f8f9fa; font-weight: bold; color: #333; }
        tr:hover { background: #f8f9fa; }
        .actions a {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            text-decoration: none;
            color: white;
            margin: 2px;
            font-size: 12px;
        }
        .btn-edit { background: #3498db; }
        .btn-delete { background: #e74c3c; }
        .btn-save { background: #27ae60; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; }
        .btn-cancel { background: #95a5a6; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 14px; display: inline-block; }
        .edit-form input, .edit-form select, .edit-form textarea {
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;
        }
        .edit-form label { font-weight: bold; display: block; margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Админ-панель</h1>
            <div class="nav-links">
                <a href="index.php">На сайт</a>
                <a href="admin.php">Обновить</a>
            </div>
        </div>
        
        <?php if ($message): ?>
            <div class="message <?= $message_type === 'success' ? 'success' : 'error' ?>">
                <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>
        
        <!-- Статистика -->
        <div class="panel">
            <h2>Статистика</h2>
            <div class="stats-panel">
                <div class="stat-card">
                    <div class="number"><?= (int)$total_users ?></div>
                    <div class="label">Всего пользователей</div>
                </div>
                <?php foreach ($stats as $stat): ?>
                    <div class="stat-card">
                        <div class="number"><?= (int)$stat['count'] ?></div>
                        <div class="label"><?= htmlspecialchars($stat['name'], ENT_QUOTES, 'UTF-8') ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <!-- Форма редактирования -->
        <?php if ($edit_mode && $edit_data): ?>
        <div class="panel">
            <h2>Редактирование записи #<?= (int)$edit_data['id'] ?></h2>
            <form method="POST" class="edit-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['admin_csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="edit_id" value="<?= (int)$edit_data['id'] ?>">
                
                <label>ФИО:</label>
                <input type="text" name="fio" value="<?= htmlspecialchars($edit_data['fio'], ENT_QUOTES, 'UTF-8') ?>" maxlength="150">
                
                <label>Телефон:</label>
                <input type="text" name="phone" value="<?= htmlspecialchars($edit_data['phone'], ENT_QUOTES, 'UTF-8') ?>" maxlength="20">
                
                <label>Email:</label>
                <input type="email" name="email" value="<?= htmlspecialchars($edit_data['email'], ENT_QUOTES, 'UTF-8') ?>" maxlength="100">
                
                <label>Дата рождения:</label>
                <input type="date" name="birth_date" value="<?= htmlspecialchars($edit_data['birth_date'], ENT_QUOTES, 'UTF-8') ?>">
                
                <label>Пол:</label>
                <select name="gender">
                    <option value="male" <?= $edit_data['gender'] === 'male' ? 'selected' : '' ?>>Мужской</option>
                    <option value="female" <?= $edit_data['gender'] === 'female' ? 'selected' : '' ?>>Женский</option>
                </select>
                
                <label>Биография:</label>
                <textarea name="biography" rows="3" maxlength="5000"><?= htmlspecialchars($edit_data['biography'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                
                <label>Контракт:</label>
                <select name="contract_accepted">
                    <option value="1" <?= $edit_data['contract_accepted'] == 1 ? 'selected' : '' ?>>Принят</option>
                    <option value="0" <?= $edit_data['contract_accepted'] == 0 ? 'selected' : '' ?>>Не принят</option>
                </select>
                
                <label>Языки:</label>
                <select name="languages[]" multiple style="height: 120px;">
                    <?php foreach ($all_languages as $lang): ?>
                        <option value="<?= htmlspecialchars($lang, ENT_QUOTES, 'UTF-8') ?>" <?= in_array($lang, $edit_data['languages']) ? 'selected' : '' ?>><?= htmlspecialchars($lang, ENT_QUOTES, 'UTF-8') ?></option>
                    <?php endforeach; ?>
                </select>
                
                <div style="margin-top: 15px;">
                    <button type="submit" class="btn-save">Сохранить</button>
                    <a href="admin.php" class="btn-cancel">Отмена</a>
                </div>
            </form>
        </div>
        <?php endif; ?>
        
        <!-- Таблица всех записей -->
        <div class="panel">
            <h2>Все записи (<?= count($applications) ?>)</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>ФИО</th>
                            <th>Телефон</th>
                            <th>Email</th>
                            <th>Дата рождения</th>
                            <th>Пол</th>
                            <th>Языки</th>
                            <th>Контракт</th>
                            <th>Логин</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($applications)): ?>
                            <tr>
                                <td colspan="10" style="text-align: center; padding: 30px;">
                                    Нет данных. <a href="index.php">Заполните форму</a>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($applications as $app): ?>
                                <tr>
                                    <td><?= (int)$app['id'] ?></td>
                                    <td><?= htmlspecialchars(substr($app['fio'], 0, 30), ENT_QUOTES, 'UTF-8') ?><?= strlen($app['fio']) > 30 ? '...' : '' ?></td>
                                    <td><?= htmlspecialchars($app['phone'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars(substr($app['email'], 0, 25), ENT_QUOTES, 'UTF-8') ?><?= strlen($app['email']) > 25 ? '...' : '' ?></td>
                                    <td><?= htmlspecialchars($app['birth_date'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= $app['gender'] === 'male' ? 'М' : 'Ж' ?></td>
                                    <td><?= htmlspecialchars($app['languages_list'] ?? '-', ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= $app['contract_accepted'] ? 'Да' : 'Нет' ?></td>
                                    <td><?= htmlspecialchars($app['login'] ?? '-', ENT_QUOTES, 'UTF-8') ?></td>
                                    <td class="actions">
                                        <a href="admin.php?action=edit&id=<?= (int)$app['id'] ?>" class="btn-edit">Изменить</a>
                                        <a href="admin.php?action=delete&id=<?= (int)$app['id'] ?>&token=<?= urlencode($_SESSION['admin_csrf_token']) ?>" 
                                           class="btn-delete" 
                                           onclick="return confirm('Точно удалить запись #<?= (int)$app['id'] ?>?')">Удалить</a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
