<?php
/**
 * Asitee — простая защита от избыточных запросов
 * Copyright (c) 2025 Itry
 * Licensed under the ItryPublic License (IPL) 2.0.
 * See LICENSE file for full terms.
 * https://github.com/yourname/asitee
 *
 * install.php — разовый установщик.
 * Создаёт таблицы в БД, db.php, asitee.php и asitee_view.php.
 * После установки этот файл нужно удалить.
 */

session_start();

define('ROOT_DIR', __DIR__);
$configFile = ROOT_DIR . '/db.php';
$alreadyInstalled = file_exists($configFile);

$error = '';
$success = false;

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$alreadyInstalled) {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $error = 'Сессия истекла, обновите страницу и попробуйте снова.';
    } else {
        $db_host = trim($_POST['db_host'] ?? 'localhost');
        $db_name = trim($_POST['db_name'] ?? '');
        $db_user = trim($_POST['db_user'] ?? '');
        $db_pass = $_POST['db_pass'] ?? '';
        $admin_pass = $_POST['admin_pass'] ?? '';
        $admin_ip = trim($_POST['admin_ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? ''));
        $threshold_count = max(1, (int)($_POST['threshold_count'] ?? 100));
        $threshold_window = max(1, (int)($_POST['threshold_window'] ?? 60));

        if ($db_name === '' || $db_user === '' || $admin_pass === '') {
            $error = 'Заполните все обязательные поля.';
        } elseif (strlen($admin_pass) < 8) {
            $error = 'Пароль администратора должен быть не короче 8 символов.';
        } elseif (!filter_var($admin_ip, FILTER_VALIDATE_IP)) {
            $error = 'Некорректный IP администратора.';
        } elseif (!preg_match('/^[A-Za-z0-9_]+$/', $db_name)) {
            $error = 'Имя базы данных может содержать только буквы, цифры и подчёркивание.';
        } else {
            try {
                $dsn = "mysql:host={$db_host};charset=utf8mb4";
                $pdo = new PDO($dsn, $db_user, $db_pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                ]);

                $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                $pdo->exec("USE `{$db_name}`");

                $pdo->exec("
                    CREATE TABLE IF NOT EXISTS asitee_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        ip_address VARCHAR(45) NOT NULL,
                        user_agent VARCHAR(500) DEFAULT NULL,
                        request_uri VARCHAR(500) DEFAULT NULL,
                        visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_ip_time (ip_address, visit_time)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                ");

                $pdo->exec("
                    CREATE TABLE IF NOT EXISTS asitee_blocked (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        ip_address VARCHAR(45) NOT NULL UNIQUE,
                        reason VARCHAR(255) DEFAULT 'Превышен лимит запросов',
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                ");

                $pdo->exec("
                    CREATE TABLE IF NOT EXISTS asitee_settings (
                        name VARCHAR(50) PRIMARY KEY,
                        value TEXT
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                ");

                $admin_hash = password_hash($admin_pass, PASSWORD_DEFAULT);
                $settings = [
                    'admin_pass_hash'  => $admin_hash,
                    'admin_ip'         => $admin_ip,
                    'threshold_count'  => (string)$threshold_count,
                    'threshold_window' => (string)$threshold_window,
                ];
                $stmt = $pdo->prepare("INSERT INTO asitee_settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)");
                foreach ($settings as $k => $v) {
                    $stmt->execute([$k, $v]);
                }

                // db.php
                $config_content = "<?php\n"
                    . "/**\n"
                    . " * Asitee — сгенерировано установщиком.\n"
                    . " * Copyright (c) 2025 Itry. Licensed under IPL 2.0.\n"
                    . " * Не публикуйте этот файл наружу.\n"
                    . " */\n"
                    . "define('ASITEE_DB_HOST', " . var_export($db_host, true) . ");\n"
                    . "define('ASITEE_DB_NAME', " . var_export($db_name, true) . ");\n"
                    . "define('ASITEE_DB_USER', " . var_export($db_user, true) . ");\n"
                    . "define('ASITEE_DB_PASS', " . var_export($db_pass, true) . ");\n\n"
                    . "function asitee_connect(): PDO {\n"
                    . "    static \$pdo = null;\n"
                    . "    if (\$pdo === null) {\n"
                    . "        \$dsn = 'mysql:host=' . ASITEE_DB_HOST . ';dbname=' . ASITEE_DB_NAME . ';charset=utf8mb4';\n"
                    . "        \$pdo = new PDO(\$dsn, ASITEE_DB_USER, ASITEE_DB_PASS, [\n"
                    . "            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,\n"
                    . "            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,\n"
                    . "            PDO::ATTR_EMULATE_PREPARES => false,\n"
                    . "        ]);\n"
                    . "    }\n"
                    . "    return \$pdo;\n"
                    . "}\n";
                file_put_contents($configFile, $config_content);
                @chmod($configFile, 0640);

                file_put_contents(ROOT_DIR . '/asitee.php', ASITEE_CORE_TEMPLATE);
                file_put_contents(ROOT_DIR . '/asitee_view.php', ASITEE_PANEL_TEMPLATE);

                $success = true;
            } catch (Exception $e) {
                $error = 'Ошибка установки: ' . $e->getMessage();
            }
        }
    }
}

// ---------------------------------------------------------------
// Шаблоны файлов, которые создаст установщик. Весь код виден прямо
// здесь — никакой загрузки извне.
// ---------------------------------------------------------------

const ASITEE_CORE_TEMPLATE = <<<'CORE'
<?php
/**
 * Asitee Core — простая защита от чрезмерного количества запросов.
 * Copyright (c) 2025 Itry. Licensed under IPL 2.0.
 *
 * Подключайте в самом начале точки входа сайта:
 *     require_once __DIR__ . '/asitee.php';
 */

require_once __DIR__ . '/db.php';

function asitee_client_ip(): string {
    // REMOTE_ADDR — самый надёжный источник, его нельзя подделать клиенту.
    // Если сайт стоит за доверенным reverse-proxy/CDN, донастройте здесь
    // получение реального IP из соответствующего заголовка, например:
    // return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function asitee_setting(PDO $pdo, string $name, $default = null) {
    static $cache = [];
    if (array_key_exists($name, $cache)) {
        return $cache[$name];
    }
    $stmt = $pdo->prepare('SELECT value FROM asitee_settings WHERE name = ?');
    $stmt->execute([$name]);
    $row = $stmt->fetch();
    $cache[$name] = $row ? $row['value'] : $default;
    return $cache[$name];
}

function asitee_deny(): void {
    http_response_code(429);
    header('Retry-After: 60');
    header('Content-Type: text/plain; charset=utf-8');
    echo "Слишком много запросов. Доступ временно ограничен.";
    exit;
}

function asitee_protect(): void {
    $pdo = asitee_connect();
    $ip = asitee_client_ip();

    $admin_ip = asitee_setting($pdo, 'admin_ip');
    if ($admin_ip !== null && hash_equals((string)$admin_ip, $ip)) {
        return; // администратор — без ограничений
    }

    $stmt = $pdo->prepare('SELECT 1 FROM asitee_blocked WHERE ip_address = ? LIMIT 1');
    $stmt->execute([$ip]);
    if ($stmt->fetch()) {
        asitee_deny();
    }

    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
    $uri = substr($_SERVER['REQUEST_URI'] ?? '', 0, 500);
    $stmt = $pdo->prepare('INSERT INTO asitee_logs (ip_address, user_agent, request_uri) VALUES (?, ?, ?)');
    $stmt->execute([$ip, $ua, $uri]);

    $window = (int)asitee_setting($pdo, 'threshold_window', 60);
    $limit  = (int)asitee_setting($pdo, 'threshold_count', 100);

    $stmt = $pdo->prepare('SELECT COUNT(*) AS cnt FROM asitee_logs WHERE ip_address = ? AND visit_time >= (NOW() - INTERVAL ? SECOND)');
    $stmt->execute([$ip, $window]);
    $count = (int)$stmt->fetch()['cnt'];

    if ($count > $limit) {
        $stmt = $pdo->prepare('INSERT IGNORE INTO asitee_blocked (ip_address, reason) VALUES (?, ?)');
        $stmt->execute([$ip, "Превышен лимит: {$count} запросов за {$window} сек."]);
        asitee_deny();
    }

    // Периодическая очистка старых логов (примерно 1% запросов)
    if (mt_rand(1, 100) === 1) {
        $pdo->exec('DELETE FROM asitee_logs WHERE visit_time < (NOW() - INTERVAL 2 DAY)');
    }
}

asitee_protect();
CORE;

const ASITEE_PANEL_TEMPLATE = <<<'PANEL'
<?php
/**
 * Asitee View — панель управления защитой от избыточных запросов.
 * Copyright (c) 2025 Itry. Licensed under IPL 2.0.
 */
session_start();
require_once __DIR__ . '/db.php';

$pdo = asitee_connect();

function asitee_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function asitee_csrf_check(): bool {
    return isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token']);
}

$error = '';

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: asitee_view.php');
    exit;
}

if (empty($_SESSION['asitee_admin']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
    if ($_SESSION['login_attempts'] > 5) {
        sleep(3); // простая защита от брутфорса
    }
    if (!asitee_csrf_check()) {
        $error = 'Форма устарела, обновите страницу.';
    } else {
        $stmt = $pdo->prepare("SELECT value FROM asitee_settings WHERE name = 'admin_pass_hash'");
        $stmt->execute();
        $hash = $stmt->fetchColumn();
        if ($hash && password_verify($_POST['password'] ?? '', $hash)) {
            session_regenerate_id(true);
            $_SESSION['asitee_admin'] = true;
            unset($_SESSION['login_attempts']);
        } else {
            $error = 'Неверный пароль.';
        }
    }
}

$isLoggedIn = !empty($_SESSION['asitee_admin']);

if ($isLoggedIn && $_SERVER['REQUEST_METHOD'] === 'POST' && asitee_csrf_check()) {
    if (isset($_POST['block_ip'])) {
        $ip = trim($_POST['block_ip']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $stmt = $pdo->prepare('INSERT IGNORE INTO asitee_blocked (ip_address, reason) VALUES (?, ?)');
            $stmt->execute([$ip, 'Заблокирован вручную']);
        }
    }
    if (isset($_POST['unblock_id'])) {
        $stmt = $pdo->prepare('DELETE FROM asitee_blocked WHERE id = ?');
        $stmt->execute([(int)$_POST['unblock_id']]);
    }
    if (isset($_POST['save_settings'])) {
        $count = max(1, (int)($_POST['threshold_count'] ?? 100));
        $window = max(1, (int)($_POST['threshold_window'] ?? 60));
        $admin_ip = trim($_POST['admin_ip'] ?? '');
        if (filter_var($admin_ip, FILTER_VALIDATE_IP)) {
            $stmt = $pdo->prepare("INSERT INTO asitee_settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)");
            $stmt->execute(['threshold_count', (string)$count]);
            $stmt->execute(['threshold_window', (string)$window]);
            $stmt->execute(['admin_ip', $admin_ip]);
        }
    }
    header('Location: asitee_view.php');
    exit;
}

$blocked = $top_ips = [];
$total_today = 0;
$settings = [];

if ($isLoggedIn) {
    $blocked = $pdo->query('SELECT * FROM asitee_blocked ORDER BY blocked_at DESC')->fetchAll();
    $top_ips = $pdo->query("
        SELECT ip_address, COUNT(*) AS cnt, MAX(visit_time) AS last_seen
        FROM asitee_logs
        WHERE visit_time >= (NOW() - INTERVAL 1 DAY)
        GROUP BY ip_address
        ORDER BY cnt DESC
        LIMIT 20
    ")->fetchAll();
    $total_today = (int)$pdo->query("SELECT COUNT(*) FROM asitee_logs WHERE visit_time >= CURDATE()")->fetchColumn();

    foreach (['threshold_count', 'threshold_window', 'admin_ip'] as $k) {
        $stmt = $pdo->prepare('SELECT value FROM asitee_settings WHERE name = ?');
        $stmt->execute([$k]);
        $settings[$k] = $stmt->fetchColumn();
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Asitee Panel</title>
<style>
body{background:#0f172a;color:#cbd5e1;font-family:Inter,system-ui,sans-serif;margin:0;padding:20px;}
.card{background:#1e2937;border-radius:12px;padding:24px;max-width:900px;margin:0 auto 20px;border:1px solid #334155;}
h1,h2{color:#f1f5f9;}
table{width:100%;border-collapse:collapse;margin-top:10px;}
th,td{padding:8px;border-bottom:1px solid #334155;text-align:left;font-size:0.9rem;}
input[type=text],input[type=password],input[type=number]{background:#0f172a;border:1px solid #334155;color:#fff;padding:8px;border-radius:6px;width:100%;box-sizing:border-box;}
button{background:#e11d48;color:#fff;border:none;padding:8px 14px;border-radius:6px;cursor:pointer;}
button:hover{background:#be123c;}
.error{background:rgba(225,29,72,.15);border:1px solid #e11d48;color:#fda4af;padding:10px;border-radius:8px;}
.badge{background:#e11d48;padding:2px 8px;border-radius:20px;font-size:0.75rem;}
a.logout{color:#38bdf8;text-decoration:none;float:right;}
</style>
</head>
<body>

<?php if (!$isLoggedIn): ?>
<div class="card" style="max-width:360px;">
    <h1>Вход в панель</h1>
    <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= asitee_csrf_token() ?>">
        <p><input type="password" name="password" placeholder="Пароль администратора" required></p>
        <button type="submit" name="login">Войти</button>
    </form>
</div>
<?php else: ?>

<div class="card">
    <a class="logout" href="?logout=1">Выйти</a>
    <h1>Asitee — панель защиты</h1>
    <p>Запросов сегодня: <strong><?= $total_today ?></strong></p>
</div>

<div class="card">
    <h2>Настройки лимита</h2>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?= asitee_csrf_token() ?>">
        <p>Лимит запросов: <input type="number" name="threshold_count" value="<?= htmlspecialchars($settings['threshold_count'] ?? 100) ?>"></p>
        <p>Окно времени (сек): <input type="number" name="threshold_window" value="<?= htmlspecialchars($settings['threshold_window'] ?? 60) ?>"></p>
        <p>IP администратора (без ограничений): <input type="text" name="admin_ip" value="<?= htmlspecialchars($settings['admin_ip'] ?? '') ?>"></p>
        <button type="submit" name="save_settings">Сохранить</button>
    </form>
</div>

<div class="card">
    <h2>Заблокированные IP</h2>
    <form method="POST" style="margin-bottom:14px;">
        <input type="hidden" name="csrf_token" value="<?= asitee_csrf_token() ?>">
        <input type="text" name="block_ip" placeholder="Заблокировать IP вручную">
        <button type="submit">Заблокировать</button>
    </form>
    <table>
        <tr><th>IP</th><th>Причина</th><th>Дата</th><th></th></tr>
        <?php foreach ($blocked as $b): ?>
        <tr>
            <td><?= htmlspecialchars($b['ip_address']) ?></td>
            <td><?= htmlspecialchars($b['reason']) ?></td>
            <td><?= htmlspecialchars($b['blocked_at']) ?></td>
            <td>
                <form method="POST" style="margin:0;">
                    <input type="hidden" name="csrf_token" value="<?= asitee_csrf_token() ?>">
                    <input type="hidden" name="unblock_id" value="<?= (int)$b['id'] ?>">
                    <button type="submit">Разблокировать</button>
                </form>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>

<div class="card">
    <h2>Топ IP за последние 24 часа</h2>
    <table>
        <tr><th>IP</th><th>Запросов</th><th>Последний визит</th></tr>
        <?php foreach ($top_ips as $t): ?>
        <tr>
            <td><?= htmlspecialchars($t['ip_address']) ?></td>
            <td><span class="badge"><?= (int)$t['cnt'] ?></span></td>
            <td><?= htmlspecialchars($t['last_seen']) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>

<?php endif; ?>
</body>
</html>
PANEL;
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Установка Asitee</title>
<style>
body{background:#0f172a;color:#cbd5e1;font-family:Inter,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;}
.card{background:#1e2937;border-radius:16px;padding:35px;width:100%;max-width:480px;border:1px solid #334155;}
h1{margin-top:0;color:#f1f5f9;border-bottom:2px solid #e11d48;padding-bottom:12px;}
label{display:block;font-size:.85rem;color:#94a3b8;margin-bottom:6px;}
input{width:100%;padding:11px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#fff;box-sizing:border-box;margin-bottom:14px;}
button{width:100%;padding:12px;background:#e11d48;color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;}
button:hover{background:#be123c;}
.error{background:rgba(225,29,72,.15);border:1px solid #e11d48;color:#fda4af;padding:12px;border-radius:8px;margin-bottom:20px;}
.success{background:rgba(16,185,129,.15);border:1px solid #10b981;color:#6ee7b7;padding:16px;border-radius:8px;}
code{background:#0f172a;padding:2px 6px;border-radius:4px;}
</style>
</head>
<body>
<div class="card">
    <h1>Установка Asitee</h1>

    <?php if ($alreadyInstalled && !$success): ?>
        <div class="error">
            Установка уже выполнена (найден файл <code>db.php</code>).<br>
            Чтобы переустановить, удалите <code>db.php</code> вручную.
        </div>
    <?php elseif ($success): ?>
        <div class="success">
            <h3 style="margin-top:0;">Готово!</h3>
            <p>Созданы файлы: <code>db.php</code>, <code>asitee.php</code>, <code>asitee_view.php</code>.</p>
        </div>
        <h2 style="font-size:1rem;color:#f1f5f9;">Что сделать дальше:</h2>
        <ol style="font-size:0.9rem;line-height:1.6;">
            <li><strong>Удалите этот файл</strong> (<code>install.php</code>) — он больше не нужен.</li>
            <li>В самое начало главной точки входа сайта (например, <code>index.php</code>) добавьте строку:<br>
                <code>require_once __DIR__ . '/asitee.php';</code>
            </li>
            <li>Если у сайта несколько точек входа — либо добавьте строку в каждую, либо подключите файл через директиву <code>auto_prepend_file</code> в конфиге PHP/хостинга.</li>
            <li>Зайдите в <code>asitee_view.php</code> и войдите с паролем администратора, который вы указали.</li>
            <li>Ограничьте доступ к <code>asitee_view.php</code> дополнительно (например, через <code>.htaccess</code> по IP), если возможно.</li>
        </ol>
    <?php else: ?>
        <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <label>Хост MySQL</label>
            <input type="text" name="db_host" value="localhost" required>
            <label>Имя базы данных</label>
            <input type="text" name="db_name" required>
            <label>Пользователь БД</label>
            <input type="text" name="db_user" required>
            <label>Пароль БД</label>
            <input type="password" name="db_pass">
            <label>Пароль администратора панели (мин. 8 символов)</label>
            <input type="password" name="admin_pass" required minlength="8">
            <label>Ваш IP (без ограничений по лимиту)</label>
            <input type="text" name="admin_ip" value="<?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '') ?>" required>
            <label>Лимит запросов за окно</label>
            <input type="text" name="threshold_count" value="100">
            <label>Окно времени, сек</label>
            <input type="text" name="threshold_window" value="60">
            <button type="submit" name="install">Установить</button>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
