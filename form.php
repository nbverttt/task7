<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Анкета разработчика</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px; line-height: 1.6; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); padding: 30px; }
        h1 { font-size: 24px; color: #333; margin-bottom: 5px; }
        .subtitle { color: #666; font-size: 14px; margin-bottom: 25px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-weight: bold; margin-bottom: 5px; color: #333; }
        .required::after { content: " *"; color: red; }
        input[type="text"], input[type="tel"], input[type="email"], input[type="date"], select, textarea {
            width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 5px; font-size: 16px; margin-top: 3px;
        }
        input.error, select.error, textarea.error { border: 2px solid red; background-color: #fff5f5; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #4a90d9; box-shadow: 0 0 5px rgba(74, 144, 217, 0.3); }
        .radio-group { display: flex; gap: 20px; margin-top: 5px; }
        .radio-group label { display: inline; font-weight: normal; }
        .radio-group input { width: auto; margin-right: 5px; }
        .radio-group.error { padding: 8px; border: 2px solid red; border-radius: 5px; background-color: #fff5f5; }
        textarea { resize: vertical; min-height: 80px; }
        select[multiple] { height: 150px; }
        .checkbox-group { display: flex; align-items: center; gap: 8px; margin-top: 5px; }
        .checkbox-group input { width: auto; }
        .checkbox-group label { display: inline; font-weight: normal; }
        button { background: #4a90d9; color: white; padding: 12px 25px; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; width: 100%; margin-top: 10px; }
        button:hover { background: #357abd; }
        .success-message { background-color: #d4edda; color: #155724; padding: 12px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #c3e6cb; }
        .error-message { background-color: #f8d7da; color: #721c24; padding: 12px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #f5c6cb; }
        .field-error-message { color: red; font-size: 12px; margin-top: 3px; display: block; }
        small { display: block; margin-top: 3px; color: #888; font-size: 12px; }
        .auth-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .btn-login { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; font-size: 14px; }
        .btn-admin { display: inline-block; padding: 10px 20px; background: #e74c3c; color: white; text-decoration: none; border-radius: 5px; font-size: 14px; }
        .logout-btn { display: inline-block; padding: 8px 15px; background: #e74c3c; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Анкета разработчика</h1>
        <p class="subtitle">Заполните форму, чтобы стать частью нашего сообщества</p>
        
        <div class="auth-buttons">
            <a href="login.php" class="btn-login">Войти как пользователь</a>
            <a href="admin.php" class="btn-admin">Войти как администратор</a>
        </div>
        
        <?php if (!empty($messages)): ?>
            <?php foreach ($messages as $msg): ?>
                <?= $msg ?>
            <?php endforeach; ?>
        <?php endif; ?>
        
        <form action="" method="POST">
            <!-- CSRF-токен -->
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
            
            <div class="form-group">
                <label class="required">ФИО</label>
                <input type="text" name="fio" 
                       class="<?= !empty($errors['fio']) ? 'error' : '' ?>"
                       value="<?= htmlspecialchars($values['fio'] ?? '', ENT_QUOTES, 'UTF-8') ?>" 
                       maxlength="150" 
                       placeholder="Иванов Иван Иванович">
                <?php if (!empty($error_messages['fio'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['fio'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Только буквы, пробелы, дефисы, точки и апострофы. Не более 150 символов.</small>
            </div>
            
            <div class="form-group">
                <label class="required">Телефон</label>
                <input type="tel" name="phone" 
                       class="<?= !empty($errors['phone']) ? 'error' : '' ?>"
                       value="<?= htmlspecialchars($values['phone'] ?? '', ENT_QUOTES, 'UTF-8') ?>" 
                       placeholder="+7 (123) 456-78-90">
                <?php if (!empty($error_messages['phone'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['phone'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Форматы: +7 (123) 456-78-90, 89123456789, 71234567890</small>
            </div>
            
            <div class="form-group">
                <label class="required">E-mail</label>
                <input type="email" name="email" 
                       class="<?= !empty($errors['email']) ? 'error' : '' ?>"
                       value="<?= htmlspecialchars($values['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>" 
                       placeholder="ivanov@example.com">
                <?php if (!empty($error_messages['email'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['email'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Форматы: name@domain.com</small>
            </div>
            
            <div class="form-group">
                <label class="required">Дата рождения</label>
                <input type="date" name="birth_date" 
                       class="<?= !empty($errors['birth_date']) ? 'error' : '' ?>"
                       value="<?= htmlspecialchars($values['birth_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                <?php if (!empty($error_messages['birth_date'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['birth_date'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Вы должны быть старше 18 лет</small>
            </div>
            
            <div class="form-group">
                <label class="required">Пол</label>
                <div class="radio-group <?= !empty($errors['gender']) ? 'error' : '' ?>">
                    <label>
                        <input type="radio" name="gender" value="male" 
                               <?= (($values['gender'] ?? '') == 'male') ? 'checked' : '' ?>> Мужской
                    </label>
                    <label>
                        <input type="radio" name="gender" value="female" 
                               <?= (($values['gender'] ?? '') == 'female') ? 'checked' : '' ?>> Женский
                    </label>
                </div>
                <?php if (!empty($error_messages['gender'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['gender'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
            </div>
            
            <div class="form-group">
                <label class="required">Любимый язык программирования</label>
                <select name="languages[]" multiple="multiple" class="<?= !empty($errors['languages']) ? 'error' : '' ?>">
                    <?php 
                    $langs = ['Pascal', 'C', 'C++', 'JavaScript', 'PHP', 'Python', 'Java', 'Haskell', 'Clojure', 'Prolog', 'Scala', 'Go'];
                    foreach ($langs as $lang): 
                    ?>
                        <option value="<?= htmlspecialchars($lang, ENT_QUOTES, 'UTF-8') ?>" <?= in_array($lang, $values['languages'] ?? []) ? 'selected' : '' ?>><?= htmlspecialchars($lang, ENT_QUOTES, 'UTF-8') ?></option>
                    <?php endforeach; ?>
                </select>
                <?php if (!empty($error_messages['languages'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['languages'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Удерживайте Ctrl (Cmd) для выбора нескольких языков</small>
            </div>
            
            <div class="form-group">
                <label>Биография</label>
                <textarea name="biography" rows="4" 
                          class="<?= !empty($errors['biography']) ? 'error' : '' ?>"
                          placeholder="Расскажите немного о себе..."><?= htmlspecialchars($values['biography'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                <?php if (!empty($error_messages['biography'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['biography'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
                <small>Не более 5000 символов</small>
            </div>
            
            <div class="form-group">
                <div class="checkbox-group">
                    <input type="checkbox" name="contract_accepted" value="1" 
                           <?= (($values['contract_accepted'] ?? '') == '1') ? 'checked' : '' ?>>
                    <label class="required">Я ознакомлен(а) с контрактом и согласен(на)</label>
                </div>
                <?php if (!empty($error_messages['contract_accepted'])): ?>
                    <span class="field-error-message"><?= htmlspecialchars($error_messages['contract_accepted'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php endif; ?>
            </div>
            
            <button type="submit">Сохранить</button>
        </form>
    </div>
</body>
</html>
