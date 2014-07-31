<?php
/*
Plugin Name: Sucuri Security - Auditing, Malware Scanner and Hardening
Plugin URI: http://wordpress.sucuri.net/
Description: The <a href="http://sucuri.net/" target="_blank">Sucuri Security</a> <em>(Auditing, Malware Scanner and Hardening)</em> plugin enables you to scan your WordPress site using <a href="http://sitecheck.sucuri.net/" target="_blank">Sucuri SiteCheck</a> right in your dashboard. SiteCheck will check for malware, spam, blacklisting and other security issues like .htaccess redirects, hidden eval code, etc. The best thing about it is it's completely free.
Author: Sucuri, INC
Version: 1.6.5
Author URI: http://sucuri.net
*/


/**
 * Main file to control the plugin.
 *
 * @package   Sucuri Plugin - SiteCheck Malware Scanner
 * @author    Yorman Arias <yorman.arias@sucuri.net>
 * @author    Daniel Cid   <dcid@sucuri.net>
 * @copyright Since 2010-2014 Sucuri Inc.
 * @license   Released under the GPL - see LICENSE file for details.
 * @link      https://wordpress.sucuri.net/
 * @since     File available since Release 0.1
 */


/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}

/**
 * Unique name of the plugin through out all the code.
 */
define('SUCURISCAN','sucuriscan');

/**
 * Current version of the plugin's code.
 */
define('SUCURISCAN_VERSION','1.6.5');

/**
 * The local URL where the plugin's files and assets are served.
 */
define('SUCURI_URL', rtrim(plugin_dir_url( __FILE__ ),'/') );

/**
 * The name of the Sucuri plugin main file.
 */
define('SUCURISCAN_PLUGIN_FILE', 'sucuri.php');

/**
 * The name of the folder where the plugin's files will be located.
 */
define('SUCURISCAN_PLUGIN_FOLDER', 'sucuri-scanner');

/**
 * The fullpath where the plugin's files will be located.
 */
define('SUCURISCAN_PLUGIN_PATH', WP_PLUGIN_DIR.'/'.SUCURISCAN_PLUGIN_FOLDER);

/**
 * The fullpath of the main plugin file.
 */
define('SUCURISCAN_PLUGIN_FILEPATH', SUCURISCAN_PLUGIN_PATH.'/'.SUCURISCAN_PLUGIN_FILE);

/**
 * Checksum of this file to check the integrity of the plugin.
 */
define('SUCURISCAN_PLUGIN_CHECKSUM', @md5_file(SUCURISCAN_PLUGIN_FILEPATH));

/**
 * Remote URL where the public Sucuri API service is running.
 */
define('SUCURISCAN_API', 'https://wordpress.sucuri.net/api/');

/**
 * Latest version of the public Sucuri API.
 */
define('SUCURISCAN_API_VERSION', 'v1');

/**
 * Remote URL where the CloudProxy API service is running.
 */
define('SUCURISCAN_CLOUDPROXY_API', 'https://waf.sucuri.net/api');

/**
 * Latest version of the CloudProxy API.
 */
define('SUCURISCAN_CLOUDPROXY_API_VERSION', 'v2');

/**
 * The maximum quantity of entries that will be displayed in the last login page.
 */
define('SUCURISCAN_LASTLOGINS_USERSLIMIT', 25);

/**
 * The maximum quantity of entries that will be displayed in the audit logs page.
 */
define('SUCURISCAN_AUDITLOGS_PER_PAGE', 50);

/**
 * The minimum quantity of seconds to wait before each filesystem scan.
 */
define('SUCURISCAN_MINIMUM_RUNTIME', 10800);

/**
 * The life time of the cache for the results of the SiteCheck scans.
 */
define('SUCURISCAN_SITECHECK_LIFETIME', 1200);

/**
 * The life time of the cache for the results of the get_plugins function.
 */
define('SUCURISCAN_GET_PLUGINS_LIFETIME', 1800);

/**
 * Miscellaneous library.
 *
 * Multiple and generic functions that will be used through out the code of
 * other libraries extending from this and functions defined in other files, be
 * aware of the hierarchy and check the other libraries for duplicated methods.
 */
class SucuriScan {

    /**
     * Class constructor.
     */
    public function __construct(){
    }

    /**
     * Generates a lowercase random string with an specific length.
     *
     * @param  integer $length Length of the string that will be generated.
     * @return string          The random string generated.
     */
    public static function random_char( $length=4 ){
        $string = '';
        $chars = range('a','z');

        for( $i=0; $i<$length; $i++ ){
            $string .= $chars[ rand(0, count($chars)-1) ];
        }

        return $string;
    }

    /**
     * Translate a given number in bytes to a human readable file size using the
     * a approximate value in Kylo, Mega, Giga, etc.
     *
     * @link   http://www.php.net/manual/en/function.filesize.php#106569
     * @param  integer $bytes    An integer representing a file size in bytes.
     * @param  integer $decimals How many decimals should be returned after the translation.
     * @return string            Human readable representation of the given number in Kylo, Mega, Giga, etc.
     */
    public static function human_filesize( $bytes=0, $decimals=2 ){
        $sz = 'BKMGTP';
        $factor = floor((strlen($bytes) - 1) / 3);
        return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
    }

    /**
     * Returns the system filepath to the relevant user uploads directory for this
     * site. This is a multisite capable function.
     *
     * @param  string $path The relative path that needs to be completed to get the absolute path.
     * @return string       The full filesystem path including the directory specified.
     */
    public static function datastore_folder_path( $path='' ){
        $wp_dir_array = wp_upload_dir();
        $wp_dir_array['basedir'] = untrailingslashit($wp_dir_array['basedir']);
        $wp_filepath = $wp_dir_array['basedir'] . '/sucuri/' . $path;

        return $wp_filepath;
    }

    /**
     * Check the nonce comming from any of the settings pages.
     *
     * @return boolean TRUE if the nonce is valid, FALSE otherwise.
     */
    public static function sucuriscan_check_options_wpnonce(){
        // Create the option_page value if permalink submission.
        if(
            !isset($_POST['option_page'])
            && isset($_POST['permalink_structure'])
        ){
            $_POST['option_page'] = 'permalink';
        }

        // Check if the option_page has an allowed value.
        if( isset($_POST['option_page']) ){
            $nonce='_wpnonce';
            $action = '';

            switch( $_POST['option_page'] ){
                case 'general':    /* no_break */
                case 'writing':    /* no_break */
                case 'reading':    /* no_break */
                case 'discussion': /* no_break */
                case 'media':      /* no_break */
                case 'options':    /* no_break */
                    $action = $_POST['option_page'] . '-options';
                    break;
                case 'permalink':
                    $action = 'update-permalink';
                    break;
            }

            // Check the nonce validity.
            if(
                !empty($action)
                && isset($_REQUEST[$nonce])
                && wp_verify_nonce($_REQUEST[$nonce], $action)
            ){
                return TRUE;
            }
        }

        return FALSE;
    }

}

/**
 * Class to process files and folders.
 *
 * Here are implemented the functions needed to open, scan, read, create files
 * and folders using the built-in PHP class SplFileInfo. The SplFileInfo class
 * offers a high-level object oriented interface to information for an individual
 * file.
 */
class SucuriScanFileInfo extends SucuriScan {

    /**
     * Whether the list of files that can be ignored from the filesystem scan will
     * be used to return the directory tree, this should be disabled when scanning a
     * directory without the need to filter the items in the list.
     *
     * @var boolean
     */
    public $ignore_files = TRUE;

    /**
     * Whether the list of folders that can be ignored from the filesystem scan will
     * be used to return the directory tree, this should be disabled when scanning a
     * path without the need to filter the items in the list.
     *
     * @var boolean
     */
    public $ignore_directories = TRUE;

    /**
     * Whether the filesystem scanner should run recursively or not.
     *
     * @var boolean
     */
    public $run_recursively = TRUE;

    /**
     * Class constructor.
     */
    public function __construct(){
    }

    /**
     * Retrieve a long text string with signatures of all the files contained
     * in the main and subdirectories of the folder specified, also the filesize
     * and md5sum of that file. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string  $directory Parent directory where the filesystem scan will start.
     * @param  string  $scan_with Set the tool used to scan the filesystem, SplFileInfo by default.
     * @param  boolean $as_array  Whether the result of the operation will be returned as an array or string.
     * @return array              List of files in the main and subdirectories of the folder specified.
     */
    public function get_directory_tree_md5( $directory='', $scan_with='spl', $as_array=FALSE ){
        $project_signatures = '';
        $abs_path = rtrim( ABSPATH, '/' );
        $files = $this->get_directory_tree($directory, $scan_with);
        sort($files);

        if( $as_array ){
            $project_signatures = array();
        }

        foreach( $files as $filepath){
            $file_checksum = @md5_file($filepath);
            $filesize = @filesize($filepath);

            if( $as_array ){
                $basename = str_replace( $abs_path . '/', '', $filepath );
                $project_signatures[$basename] = array(
                    'filepath' => $filepath,
                    'checksum' => $file_checksum,
                    'filesize' => $filesize,
                    'filetime' => filectime($filepath),
                );
            } else {
                $filepath = str_replace( $abs_path, $abs_path . '/', $filepath );
                $project_signatures .= sprintf(
                    "%s%s%s%s\n",
                    $file_checksum,
                    $filesize,
                    chr(32),
                    $filepath
                );
            }
        }

        return $project_signatures;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @param  string $scan_with Set the tool used to scan the filesystem, SplFileInfo by default.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    public function get_directory_tree($directory='', $scan_with='spl'){
        if( file_exists($directory) && is_dir($directory) ){
            $tree = array();

            switch( $scan_with ){
                case 'spl':
                    if( $this->is_spl_available() ){
                        $tree = $this->get_directory_tree_with_spl($directory);
                    } else {
                        $tree = $this->get_directory_tree($directory, 'opendir');
                    }
                    break;

                case 'glob':
                    $tree = $this->get_directory_tree_with_glob($directory);
                    break;

                case 'opendir':
                    $tree = $this->get_directory_tree_with_opendir($directory);
                    break;

                default:
                    $tree = $this->get_directory_tree($directory, 'spl');
                    break;
            }

            return $tree;
        }

        return FALSE;
    }

    /**
     * Check whether the built-in class SplFileObject is available in the system
     * or not, it is required to have PHP >= 5.1.0. The SplFileObject class offers
     * an object oriented interface for a file.
     *
     * @link http://www.php.net/manual/en/class.splfileobject.php
     *
     * @return boolean Whether the PHP class "SplFileObject" is available or not.
     */
    public static function is_spl_available(){
        return (bool) class_exists('SplFileObject');
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @link http://www.php.net/manual/en/class.recursivedirectoryiterator.php
     * @see  RecursiveDirectoryIterator extends FilesystemIterator
     * @see  FilesystemIterator         extends DirectoryIterator
     * @see  DirectoryIterator          extends SplFileInfo
     * @see  SplFileInfo
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_spl($directory=''){
        $files = array();
        $filepath = realpath($directory);

        if( !class_exists('FilesystemIterator') ){
            return $this->get_directory_tree($directory, 'opendir');
        }

        if( $this->run_recursively ){
            $flags = FilesystemIterator::KEY_AS_PATHNAME
                | FilesystemIterator::CURRENT_AS_FILEINFO
                | FilesystemIterator::SKIP_DOTS
                | FilesystemIterator::UNIX_PATHS;
            $objects = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($filepath, $flags),
                RecursiveIteratorIterator::SELF_FIRST
            );
        } else {
            $objects = new DirectoryIterator($filepath);
        }

        foreach( $objects as $filepath => $fileinfo ){
            if( $this->run_recursively ){
                $directory = dirname($filepath);
                $filename = $fileinfo->getFilename();
            } else {
                if( $fileinfo->isDot() || $fileinfo->isDir() ){ continue; }

                $directory = $fileinfo->getPath();
                $filename = $fileinfo->getFilename();
                $filepath = $directory . '/' . $filename;
            }

            if( $this->ignore_folderpath($directory, $filename) ){ continue; }
            if( $this->ignore_filepath($filename) ){ continue; }

            $files[] = $filepath;
        }

        return $files;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_glob($directory=''){
        $files = array();

        $directory_pattern = sprintf( '%s/*', rtrim($directory,'/') );
        $files_found = glob($directory_pattern);

        if( is_array($files_found) ){
            foreach( $files_found as $filepath ){
                $filepath = realpath($filepath);
                $directory = dirname($filepath);
                $filename = array_pop(explode('/', $filepath));

                if( is_dir($filepath) ){
                    if( $this->ignore_folderpath($directory, $filename) ){ continue; }

                    if( $this->run_recursively ){
                        $sub_files = $this->get_directory_tree_with_opendir($filepath);
                        $files = array_merge($files, $sub_files);
                    }
                } else {
                    if( $this->ignore_filepath($filename) ){ continue; }
                    $files[] = $filepath;
                }
            }
        }

        return $files;
    }

    /**
     * Retrieve a list with all the files contained in the main and subdirectories
     * of the folder specified. Some folders and files will be ignored depending
     * on some rules defined by the developer.
     *
     * @param  string $directory Parent directory where the filesystem scan will start.
     * @return array             List of files in the main and subdirectories of the folder specified.
     */
    private function get_directory_tree_with_opendir($directory=''){
        $dh = @opendir($directory);
        if( !$dh ){ return FALSE; }

        $files = array();
        while( ($filename = readdir($dh)) !== FALSE ){
            $filepath = realpath($directory.'/'.$filename);

            if( is_dir($filepath) ){
                if( $this->ignore_folderpath($directory, $filename) ){ continue; }

                if( $this->run_recursively ){
                    $sub_files = $this->get_directory_tree_with_opendir($filepath);
                    $files = array_merge($files, $sub_files);
                }
            } else {
                if( $this->ignore_filepath($filename) ){ continue; }
                $files[] = $filepath;
            }
        }

        closedir($dh);
        return $files;
    }

    /**
     * Skip some specific directories and filepaths from the filesystem scan.
     *
     * @param  string  $directory Directory where the scanner is located at the moment.
     * @param  string  $filename  Name of the folder or file being scanned at the moment.
     * @return boolean            Either TRUE or FALSE representing that the scan should ignore this folder or not.
     */
    private function ignore_folderpath( $directory='', $filename='' ){
        // Ignoring current and parent folders.
        if( $filename == '.' || $filename == '..' ){ return TRUE; }

        if( $this->ignore_directories ){
            $filepath = realpath( $directory . '/' . $filename );
            $pattern = '/\/wp-content\/(uploads|cache|backup|w3tc)/';

            if( preg_match($pattern, $filepath) ){
                return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * Skip some specific files from the filesystem scan.
     *
     * @param  string  $filename Name of the folder or file being scanned at the moment.
     * @return boolean           Either TRUE or FALSE representing that the scan should ignore this filename or not.
     */
    private function ignore_filepath( $filename='' ){
        if( !$this->ignore_files ){ return FALSE; }

        // Ignoring backup files from our clean ups.
        if( strpos($filename, '_sucuribackup.') !== FALSE ){ return TRUE; }

        // Any file maching one of these rules WILL NOT be ignored.
        if(
            ( strpos($filename, '.php')      !== FALSE) ||
            ( strpos($filename, '.htm')      !== FALSE) ||
            ( strpos($filename, '.js')       !== FALSE) ||
            ( strcmp($filename, '.htaccess') == 0     ) ||
            ( strcmp($filename, 'php.ini')   == 0     )
        ){ return FALSE; }

        return TRUE;
    }

    /**
     * Retrieve a list of unique directory paths.
     *
     * @param  array $dir_tree A list of files under a directory.
     * @return array           A list of unique directory paths.
     */
    public function get_diretories_only( $dir_tree=array() ){
        $dirs = array();

        if( is_string($dir_tree) ){
            $dir_tree = $this->get_directory_tree($dir_tree);
        }

        foreach( $dir_tree as $filepath ){
            $dir_path = dirname($filepath);

            if( !in_array($dir_path, $dirs) ){
                $dirs[] = $dir_path;
            }
        }

        return $dirs;
    }

    /**
     * Remove a directory recursively.
     *
     * @param  string  $directory Path of the existing directory that will be removed.
     * @return boolean            TRUE if all the files and folder inside the directory were removed.
     */
    public function remove_directory_tree( $directory='' ){
        $all_removed = TRUE;
        $dir_tree = $this->get_directory_tree($directory);

        if( $dir_tree ){
            $dirs_only = array();

            foreach( $dir_tree as $filepath ){
                if( is_file($filepath) ){
                    $removed = @unlink($filepath);

                    if( !$removed ){
                        $all_removed = FALSE;
                    }
                }

                elseif( is_dir($filepath) ){
                    $dirs_only[] = $filepath;
                }
            }

            if( !function_exists('sucuriscan_strlen_diff') ){
                /**
                 * Evaluates the difference between the length of two strings.
                 *
                 * @param  string  $a First string of characters that will be measured.
                 * @param  string  $b Second string of characters that will be measured.
                 * @return integer    The difference in length between the two strings.
                 */
                function sucuriscan_strlen_diff( $a='', $b='' ){
                    return strlen($b) - strlen($a);
                }
            }

            usort($dirs_only, 'sucuriscan_strlen_diff');

            foreach( $dirs_only as $dir_path ){
                @rmdir($dir_path);
            }
        }

        return $all_removed;
    }

}

/**
 * Class responsible for the processing of all the tasks associated to the database.
 *
 * Here are implemented the functions needed to rename tables, generate random names,
 * change the Wordpress table prefix and modify the name of all the options linked to
 * the previous database prefix.
 */
class SucuriScanDatabase extends SucuriScan {

    /**
     * List all database tables in a clean array of strings.
     *
     * @return array Array of strings.
     */
    public function get_dbtables(){
        global $wpdb;

        $table_names = array();
        $tables = $wpdb->get_results('SHOW TABLES', ARRAY_N);

        foreach($tables as $table){
            $table_names[] = $table[0];
        }

        return $table_names;
    }

    /**
     * Set a new database table prefix to improve the security.
     *
     * @return void
     */
    public function new_table_prefix(){
        $new_table_prefix = $this->random_char( rand(4,7) ).'_';
        $this->set_table_prefix($new_table_prefix);
    }

    /**
     * Reset the database table prefix with the default value 'wp_'.
     *
     * @return void
     */
    public function reset_table_prefix(){
        $this->set_table_prefix('wp_');
    }

    /**
     * Set a new table prefix and changes table names, options, configuration files, etc.
     *
     * @param  string $new_table_prefix The new table prefix.
     * @return void
     */
    private function set_table_prefix( $new_table_prefix='wp_' ){
        $resp_parts = array();

        // Set the new table prefix in the configuration file.
        $resp_parts[] = $this->new_table_prefix_wpconfig($new_table_prefix);

        // Update options table with the new table prefix.
        $resp_parts[] = $this->new_table_prefix_optionstable($new_table_prefix);

        // Update usermeta table with the new table prefix.
        $resp_parts[] = $this->new_table_prefix_usermetatable($new_table_prefix);

        // Rename table names with the new table prefix.
        $resp_parts[] = $this->new_table_prefix_tablerename($new_table_prefix);

        foreach( $resp_parts as $response ){
            if( $response['process'] !== TRUE ){
                sucuriscan_error( $response['message'] );
            }
        }
    }

    /**
     * Using the new database table prefix, it modifies the main configuration file with that new value.
     *
     * @param  string $new_table_prefix
     * @return array  An array with two default indexes containing the result of the operation and a message.
     */
    private function new_table_prefix_wpconfig( $new_table_prefix='' ){
        global $wpdb;

        $response = array( 'process'=>FALSE, 'message'=>'' );
        $wp_config_path = sucuriscan_get_wpconfig_path();

        if( file_exists($wp_config_path) ){
            @chmod($wp_config_path, 0777);

            if( is_writable($wp_config_path) ){
                $new_wpconfig = '';
                $wpconfig_lines = @file($wp_config_path);

                foreach( $wpconfig_lines as $line ){
                    $line = str_replace("\n", '', $line);

                    if( preg_match('/.*\$table_prefix([ ]+)?=.*/', $line, $match) ){
                        $line = str_replace($wpdb->prefix, $new_table_prefix, $match[0]);
                    }

                    $new_wpconfig .= "{$line}\n";
                }

                $handle = fopen($wp_config_path, 'w');
                @fwrite($handle, $new_wpconfig);
                @fclose($handle);
                @chmod($wp_config_path, 0644);

                $response['process'] = TRUE;
                $response['message'] = 'Main configuration file modified.';
            } else {
                $response['message'] = 'Main configuration file is not writable, you will need to put the new
                    table prefix <code>'.$new_table_prefix.'</code> manually in <code>wp-config.php</code>.';
            }
        } else {
            $response['message'] = 'Main configuration file was not located: <code>'.$wp_config_path.'</code>.';
        }

        return $response;
    }

    /**
     * Returns a list of all the tables in the selected database containing the same prefix.
     *
     * @param  string $prefix A text string used to filter the tables with a specific prefix.
     * @return array          A list of all the tables with the prefix specified.
     */
    public function get_prefixed_tables( $prefix='' ){
        global $wpdb;

        $tables = array();
        $prefix = empty($prefix) ? $wpdb->prefix : $prefix;
        $db_tables = $this->get_dbtables();

        foreach( $db_tables as $table_name ){
            if( preg_match("/^{$prefix}/", $table_name) ){
                $tables[] = $table_name;
            }
        }

        return $tables;
    }

    /**
     * Using the new database table prefix, it modifies the name of all tables with the new value.
     *
     * @param  string $new_table_prefix
     * @return array  An array with two default indexes containing the result of the operation and a message.
     */
    private function new_table_prefix_tablerename( $new_table_prefix='' ){
        global $wpdb;

        $response = array( 'process'=>FALSE, 'message'=>'' );
        $db_tables = $this->get_prefixed_tables();

        $renamed_count = 0;
        $total_tables = count($db_tables);
        $tables_not_renamed = array();

        foreach( $db_tables as $table_name ){
            $table_new_name = $new_table_prefix . str_replace($wpdb->prefix, '', $table_name);
            $sql = 'RENAME TABLE `%s` TO `%s`';

            /* Don't use WPDB->Prepare() */
            if( $wpdb->query(sprintf($sql, $table_name, $table_new_name))===FALSE ){
                $tables_not_renamed[] = $table_name;
            } else {
                $renamed_count += 1;
            }
        }

        $response['message'] = 'Database tables renamed: '.$renamed_count.' out of '.$total_tables;

        if( $renamed_count>0 && $renamed_count==$total_tables ){
            $response['process'] = TRUE;
            $error = $wpdb->set_prefix($new_table_prefix);

            if( is_wp_error($error) ){
                foreach( $error->errors as $error_index=>$error_data ){
                    if( is_array($error_data) ){
                        foreach( $error_data as $error_data_value ){
                            $response['message'] .= chr(32) . $error_data_value . '.';
                        }
                    }
                }
            }
        } else {
            $response['message'] .= '<br>These tables were not renamed, you will need to do it manually:';
            $response['message'] .= chr(32) . implode( ',' . chr(32), $table_not_renamed );
        }

        return $response;
    }

    /**
     * Using the new database table prefix, it modifies the name of all options with the new value.
     *
     * @param  string $new_table_prefix
     * @return array  An array with two default indexes containing the result of the operation and a message.
     */
    private function new_table_prefix_optionstable( $new_table_prefix='' ){
        global $wpdb;

        $response = array( 'process'=>TRUE, 'message'=>'' );
        $results = $wpdb->get_results("SELECT option_id, option_name FROM {$wpdb->prefix}options WHERE option_name LIKE '{$wpdb->prefix}%'");

        foreach( $results as $row ){
            $row->new_option_name = $new_table_prefix.str_replace($wpdb->prefix, '', $row->option_name);
            $sql = "UPDATE {$wpdb->prefix}options SET option_name=%s WHERE option_id=%s LIMIT 1";

            if( $wpdb->query($wpdb->prepare($sql, $row->new_option_name, $row->option_id))===FALSE ){
                $response['process'] = FALSE;
            }
        }

        $response['message'] = $response['process']
            ? 'Database table options updated.'
            : 'Some entries in the database table <strong>Options</strong> were not updated';

        return $response;
    }

    /**
     * Using the new database table prefix, it modifies the name of all usermeta keys with the new value.
     *
     * @param  string $new_table_prefix
     * @return array  An array with two default indexes containing the result of the operation and a message.
     */
    private function new_table_prefix_usermetatable( $new_table_prefix='' ){
        global $wpdb;

        $response = array( 'process'=>TRUE, 'message'=>'' );
        $results = $wpdb->get_results("SELECT umeta_id, meta_key FROM {$wpdb->prefix}usermeta WHERE meta_key LIKE '{$wpdb->prefix}%'");

        foreach( $results as $row ){
            $row->new_meta_key = $new_table_prefix.str_replace($wpdb->prefix, '', $row->meta_key);
            $sql = "UPDATE {$wpdb->prefix}usermeta SET meta_key=%s WHERE umeta_id=%s LIMIT 1";

            if( $wpdb->query($wpdb->prepare($sql, $row->new_meta_key, $row->umeta_id))===FALSE ){
                $response['process'] = FALSE;
            }
        }

        $response['message'] = $response['process']
            ? 'Database table usermeta updated.'
            : 'Some entries in the database table <strong>UserMeta</strong> were not updated';

        return $response;
    }

}

/**
 * File-based cache library.
 *
 * WP_Object_Cache [1] is WordPress' class for caching data which may be
 * computationally expensive to regenerate, such as the result of complex
 * database queries. However the object cache is non-persistent. This means that
 * data stored in the cache resides in memory only and only for the duration of
 * the request. Cached data will not be stored persistently across page loads
 * unless of the installation of a 3party persistent caching plugin [2].
 *
 * [1] http://codex.wordpress.org/Class_Reference/WP_Object_Cache
 * [2] http://codex.wordpress.org/Class_Reference/WP_Object_Cache#Persistent_Caching
 */
class SucuriScanCache extends SucuriScan {

    /**
     * The unique name (or identifier) of the file with the data.
     *
     * The file should be located in the same folder where the dynamic data
     * generated by the plugin is stored, and using the following format [1], it
     * most be a PHP file because it is expected to have an exit point in the first
     * line of the file causing it to stop the execution if a unauthorized user
     * tries to access it directly.
     *
     * [1] /public/data/sucuri-DATASTORE.php
     *
     * @var null|string
     */
    private $datastore = NULL;

    /**
     * The full path of the datastore file.
     *
     * @var string
     */
    private $datastore_path = '';

    /**
     * Whether the datastore file is usable or not.
     *
     * This variable will only be TRUE if the datastore file specified exists, is
     * writable and readable, in any other case it will always be FALSE.
     *
     * @var boolean
     */
    private $usable_datastore = FALSE;

    /**
     * Class constructor.
     *
     * @param  string $datastore Unique name (or identifier) of the file with the data.
     * @return void
     */
    public function __construct( $datastore='' ){
        $this->datastore = $datastore;
        $this->datastore_path = $this->datastore_file_path();
        $this->usable_datastore = (bool) $this->datastore_path;
    }

    /**
     * Default attributes for every datastore file.
     *
     * @return string Default attributes for every datastore file.
     */
    private function datastore_default_info(){
        $attrs = array(
            'datastore' => $this->datastore,
            'created_on' => time(),
            'updated_on' => time(),
        );

        return $attrs;
    }

    /**
     * Default content of every datastore file.
     *
     * @param  array  $finfo Rainbow table with the key names and decoded values.
     * @return string        Default content of every datastore file.
     */
    private function datastore_info( $finfo=array() ){
        $attrs = $this->datastore_default_info();
        $info_is_available = (bool) isset($finfo['info']);
        $info  = "<?php\n";

        foreach( $attrs as $attr_name => $attr_value ){
            if(
                $info_is_available
                && $attr_name != 'updated_on'
                && isset($finfo['info'][$attr_name])
            ){
                $attr_value = $finfo['info'][$attr_name];
            }

            $info .= sprintf( "// %s=%s;\n", $attr_name, $attr_value );
        }

        $info .= "exit(0);\n";
        $info .= "?>\n";

        return $info;
    }

    /**
     * Check if the datastore file exists, if it's writable and readable by the same
     * user running the server, in case that it does not exists the function will
     * tries to create it by itself with the right permissions to use it.
     *
     * @return string The full path where the datastore file is located, FALSE otherwise.
     */
    private function datastore_file_path(){
        if( !is_null($this->datastore) ){
            $folder_path = $this->datastore_folder_path();
            $file_path = $folder_path . 'sucuri-' . $this->datastore . '.php';

            // Create the datastore file is it does not exists and the folder is writable.
            if(
                !file_exists($file_path)
                && is_writable($folder_path)
            ){
                @file_put_contents( $file_path, $this->datastore_info(), LOCK_EX );
            }

            // Continue the operation after an attemp to create the datastore file.
            if(
                file_exists($file_path)
                && is_writable($file_path)
                && is_readable($file_path)
            ){
                return $file_path;
            }
        }

        return FALSE;
    }

    /**
     * Check whether a key has a valid name or not.
     *
     * @param  string  $key Unique name to identify the data in the datastore file.
     * @return boolean      TRUE if the format of the key name is valid, FALSE otherwise.
     */
    private function valid_key_name( $key='' ){
        $key = trim($key);

        if( !empty($key) ){
            return (bool) preg_match('/^([a-zA-Z_]+)$/', $key);
        }

        return FALSE;
    }

    /**
     * Update the content of the datastore file with the new entries.
     *
     * @param  array   $finfo Rainbow table with the key names and decoded values.
     * @return boolean        TRUE if the operation finished successfully, FALSE otherwise.
     */
    private function save_new_entries( $finfo=array() ){
        $data_string = $this->datastore_info($finfo);

        if( !empty($finfo) ){
            foreach( $finfo['entries'] as $key => $data ){
                if( $this->valid_key_name($key) ){
                    $data = json_encode($data);
                    $data_string .= sprintf( "%s:%s\n", $key, $data );
                }
            }
        }

        $saved = @file_put_contents( $this->datastore_path, $data_string, LOCK_EX );

        return (bool) $saved;
    }

    /**
     * Retrieve and parse the datastore file, and generate a rainbow table with the
     * key names and decoded data as the values of each entry. Duplicated key names
     * will be removed automatically while adding the keys to the array and their
     * values will correspond to the first occurrence found in the file.
     *
     * @param  boolean $assoc When TRUE returned objects will be converted into associative arrays.
     * @return array          Rainbow table with the key names and decoded values.
     */
    private function get_datastore_content( $assoc=FALSE ){
        $data_object = array(
            'info' => array(),
            'entries' => array(),
        );

        if( $this->usable_datastore ){
            $data_lines = @file($this->datastore_path);

            if( !empty($data_lines) ){
                foreach( $data_lines as $line ){
                    $line = trim($line);

                    if( preg_match('/^\/\/ ([a-z_]+)=(.*);$/', $line, $match) ){
                        $data_object['info'][$match[1]] = $match[2];
                    }

                    elseif( preg_match('/^([a-z_]+):(.+)/', $line, $match) ){
                        if(
                            $this->valid_key_name($match[1])
                            && !array_key_exists($match[1], $data_object)
                        ){
                            $data_object['entries'][$match[1]] = json_decode( $match[2], $assoc );
                        }
                    }
                }
            }
        }

        return $data_object;
    }

    /**
     * Retrieve the headers of the datastore file.
     *
     * Each datastore file has a list of attributes at the beginning of the it with
     * information like the creation and last update time. If you are extending the
     * functionality of these headers please refer to the function that contains the
     * default attributes and their values [1].
     *
     * [1] SucuriScanCache::datastore_default_info()
     *
     * @return array Default content of every datastore file.
     */
    public function get_datastore_info(){
        $finfo = $this->get_datastore_content();

        if( !empty($finfo['info']) ){
            return $finfo['info'];
        }

        return FALSE;
    }

    /**
     * Get the total number of unique entries in the datastore file.
     *
     * @param  array   $finfo Rainbow table with the key names and decoded values.
     * @return integer        Total number of unique entries found in the datastore file.
     */
    public function get_count( $finfo=NULL ){
        if( !is_array($finfo) ){
            $finfo = $this->get_datastore_content();
        }

        return count($finfo['entries']);
    }

    /**
     * Check whether the last update time of the datastore file has surpassed the
     * lifetime specified for a key name. This function is the only one related with
     * the caching process, any others besides this are just methods used to handle
     * the data inside those files.
     *
     * @param  integer $lifetime Life time of the key in the datastore file.
     * @param  array   $finfo    Rainbow table with the key names and decoded values.
     * @return boolean           TRUE if the life time of the data has expired, FALSE otherwise.
     */
    public function data_has_expired( $lifetime=0, $finfo=NULL ){
        if( is_null($finfo) ){
            $finfo = $this->get_datastore_content();
        }

        if( $lifetime > 0 && !empty($finfo['info']) ){
            $diff_time = time() - intval($finfo['info']['updated_on']);

            if( $diff_time >= $lifetime ){
                return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * Execute the action using the key name and data specified.
     *
     * @param  string  $key      Unique name to identify the data in the datastore file.
     * @param  string  $data     Mixed data stored in the datastore file following the unique key name.
     * @param  string  $action   Either add, set, get, or delete.
     * @param  integer $lifetime Life time of the key in the datastore file.
     * @param  boolean $assoc    When TRUE returned objects will be converted into associative arrays.
     * @return boolean           TRUE if the operation finished successfully, FALSE otherwise.
     */
    private function handle_key_data( $key='', $data=NULL, $action='', $lifetime=0, $assoc=FALSE ){
        if( preg_match('/^(add|set|get|delete)$/', $action) ){
            if( $this->valid_key_name($key) && $this->usable_datastore ){
                $finfo = $this->get_datastore_content($assoc);

                switch( $action ){
                    case 'add': /* no_break */
                    case 'set':
                        $finfo['entries'][$key] = $data;
                        return $this->save_new_entries($finfo);
                        break;
                    case 'get':
                        if(
                            !$this->data_has_expired($lifetime, $finfo)
                            && array_key_exists($key, $finfo['entries'])
                        ){
                            return $finfo['entries'][$key];
                        }
                        break;
                    case 'delete':
                        unset($finfo['entries'][$key]);
                        return $this->save_new_entries($finfo);
                        break;
                }
            }
        }

        return FALSE;
    }

    /**
     * JSON-encode the data and store it in the datastore file identifying it with
     * the key name, the data will be added to the file even if the key is
     * duplicated, but when getting the value of the same key later again it will
     * return only the value of the first occurrence found in the file.
     *
     * @param  string  $key  Unique name to identify the data in the datastore file.
     * @param  string  $data Mixed data stored in the datastore file following the unique key name.
     * @return boolean       TRUE if the data was stored successfully, FALSE otherwise.
     */
    public function add( $key='', $data='' ){
        return $this->handle_key_data( $key, $data, 'add' );
    }

    /**
     * Update the data of all the key names matching the one specified.
     *
     * @param  string  $key  Unique name to identify the data in the datastore file.
     * @param  string  $data Mixed data stored in the datastore file following the unique key name.
     * @return boolean       TRUE if the data was stored successfully, FALSE otherwise.
     */
    public function set( $key='', $data='' ){
        return $this->handle_key_data( $key, $data, 'set' );
    }

    /**
     * Retrieve the first occurrence of the key found in the datastore file.
     *
     * @param  string  $key      Unique name to identify the data in the datastore file.
     * @param  integer $lifetime Life time of the key in the datastore file.
     * @param  boolean $assoc    When TRUE returned objects will be converted into associative arrays.
     * @return string            Mixed data stored in the datastore file following the unique key name.
     */
    public function get( $key='', $lifetime=0, $assoc=FALSE ){
        $assoc = ( $assoc == 'array' ? TRUE : $assoc );

        return $this->handle_key_data( $key, NULL, 'get', $lifetime, $assoc );
    }

    /**
     * Delete any entry from the datastore file matching the key name specified.
     *
     * @param  string  $key Unique name to identify the data in the datastore file.
     * @return boolean      TRUE if the entries were removed, FALSE otherwise.
     */
    public function delete( $key='' ){
        return $this->handle_key_data( $key, NULL, 'delete' );
    }

    /**
     * Remove all the entries from the datastore file.
     *
     * @return boolean Always TRUE unless the datastore file is not writable.
     */
    public function flush(){
        $finfo = $this->get_datastore_content();

        return $this->save_new_entries($finfo);
    }

}

/**
 * Check whether the current site is working as a multi-site instance.
 *
 * @return boolean Either TRUE or FALSE in case WordPress is being used as a multi-site instance.
 */
function sucuriscan_is_multisite(){
    if( function_exists('is_multisite') && is_multisite() ){ return TRUE; }
    return FALSE;
}

/**
 * Check whether the IP address specified is a valid IPv4 format.
 *
 * @param  string  $remote_addr The host IP address.
 * @return boolean              TRUE if the address specified is a valid IPv4 format, FALSE otherwise.
 */
function sucuriscan_is_valid_ipv4( $remote_addr='' ){
    if( preg_match('/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/', $remote_addr, $match) ){
        for( $i=0; $i<4; $i++ ){
            if( $match[$i] > 255 ){ return FALSE; }
        }

        return TRUE;
    }

    return FALSE;
}

if( !function_exists('sucuriscan_init') ){
    /**
     * Initialization code for the plugin.
     *
     * The initial variables and information needed by the plugin during the
     * execution of other functions will be generated. Things like the real IP
     * address of the client when it has been forwarded or it's behind an external
     * service like a Proxy.
     *
     * @return void
     */
    function sucuriscan_init(){
        if(
            isset($_SERVER['HTTP_X_FORWARDED_FOR'])
            && preg_match("/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/", $_SERVER['HTTP_X_FORWARDED_FOR'])
            && sucuriscan_is_valid_ipv4($_SERVER['HTTP_X_FORWARDED_FOR'])
        ){
            $_SERVER['SUCURIREAL_REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'];
            $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
    }

    add_action('init', 'sucuriscan_init', 1);
}

if( !function_exists('sucuriscan_create_uploaddir') ){
    /**
     * Create a folder in the WordPress upload directory where the plugin will
     * store all the temporal or dynamic information.
     *
     * @return void
     */
    function sucuriscan_create_uploaddir(){
        $plugin_upload_folder = sucuriscan_dir_filepath();

        if( !file_exists($plugin_upload_folder) ){
            if( @mkdir($plugin_upload_folder) ){
                // Create last-logins datastore file.
                sucuriscan_lastlogins_datastore_exists();

                // Create a htaccess file to deny access from all.
                @file_put_contents(
                    $plugin_upload_folder . '/.htaccess',
                    "Order Deny,Allow\nDeny from all",
                    LOCK_EX
                );

                // Create an index.html to avoid directory listing.
                @file_put_contents(
                    $plugin_upload_folder . '/index.html',
                    '<!-- Attemp to prevent the directory listing. -->',
                    LOCK_EX
                );
            } else {
                sucuriscan_error(
                    'Data folder does not exists and could not be created. You will need to
                    create this folder manually and give it write permissions:<br><br><code>'
                    . $plugin_upload_folder . '</code>'
                );
            }
        }
    }

    add_action('admin_init', 'sucuriscan_create_uploaddir');
}

if( !function_exists('sucuriscan_admin_script_style_registration') ){
    /**
     * Define which javascript and css files will be loaded in the header of the page.
     * @return void
     */
    function sucuriscan_admin_script_style_registration(){
        $asset_version = '';

        if( strlen(SUCURISCAN_PLUGIN_CHECKSUM) >= 7 ){
            $asset_version = substr(SUCURISCAN_PLUGIN_CHECKSUM, 0, 7);
        }

        wp_register_style( 'sucuriscan', SUCURI_URL . '/inc/css/sucuriscan-default-css.css', array(), $asset_version );
        wp_register_script( 'sucuriscan', SUCURI_URL . '/inc/js/sucuriscan-scripts.js', array(), $asset_version );

        wp_enqueue_style( 'sucuriscan' );
        wp_enqueue_script( 'sucuriscan' );
    }

    add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );
}

/**
 * Returns the system filepath to the relevant user uploads directory for this
 * site. This is a multisite capable function.
 *
 * @param  string $path The relative path that needs to be completed to get the absolute path.
 * @return string       The full filesystem path including the directory specified.
 */
function sucuriscan_dir_filepath($path = ''){
    return SucuriScan::datastore_folder_path($path);
}

/**
 * List an associative array with the sub-pages of this plugin.
 *
 * @param  boolean $for_navbar Either TRUE or FALSE indicanting that the first page will be named Dashboard.
 * @return array               List of pages and sub-pages of this plugin.
 */
function sucuriscan_pages( $for_navbar=FALSE ){
    $pages = array(
        'sucuriscan' => 'Dashboard',
        'sucuriscan_scanner' => 'Malware Scan',
        'sucuriscan_monitoring' => 'Firewall (WAF)',
        'sucuriscan_hardening' => 'Hardening',
        'sucuriscan_posthack' => 'Post-Hack',
        'sucuriscan_lastlogins' => 'Last Logins',
        'sucuriscan_settings' => 'Settings',
        'sucuriscan_infosys' => 'Site Info',
    );

    return $pages;
}

/**
 * Generate the menu and submenus for the plugin in the admin interface.
 *
 * @return void
 */
function sucuriscan_menu(){
    // Add main menu link.
    add_menu_page(
        'Sucuri Security',
        'Sucuri Security',
        'manage_options',
        'sucuriscan',
        'sucuriscan_page',
        SUCURI_URL . '/inc/images/menu-icon.png'
    );

    $sub_pages = sucuriscan_pages();

    foreach( $sub_pages as $sub_page_func => $sub_page_title ){
        $page_func = $sub_page_func . '_page';

        add_submenu_page(
            'sucuriscan',
            $sub_page_title,
            $sub_page_title,
            'manage_options',
            $sub_page_func,
            $page_func
        );
    }
}

if( !function_exists('sucuriscan_handle_old_plugin') ){
    /**
     * Remove the old Sucuri plugins considering that with the new version (after
     * 1.6.0) all the functionality of the others will be merged here, this will
     * remove duplicated functionality, duplicated bugs and/or duplicated
     * maintenance reports allowing us to focus in one unique project.
     *
     * @return void
     */
    function sucuriscan_handle_old_plugin(){
        $sucuri_fileinfo = new SucuriScanFileInfo();
        $sucuri_fileinfo->ignore_files = FALSE;
        $sucuri_fileinfo->ignore_directories = FALSE;

        $plugins = array(
            'sucuri-wp-plugin/sucuri.php',
            'sucuri-cloudproxy-waf/cloudproxy.php',
        );

        foreach( $plugins as $plugin ){
            $plugin_directory = dirname( WP_PLUGIN_DIR . '/' . $plugin );

            if( file_exists($plugin_directory) ){
                if( is_plugin_active($plugin) ){
                    deactivate_plugins($plugin);
                }

                $plugin_removed = $sucuri_fileinfo->remove_directory_tree($plugin_directory);
            }
        }
    }

    add_action('admin_init', 'sucuriscan_handle_old_plugin');
}

/**
 * Initialize the execute of the main plugin's functions.
 *
 * This will load the menu options in the WordPress administrator panel, and
 * execute the bootstrap function of the plugin.
 */
add_action('admin_menu', 'sucuriscan_menu');
add_action('sucuriscan_scheduled_scan', 'sucuriscan_filesystem_scan');
remove_action('wp_head', 'wp_generator');

/**
 * Validate email address.
 *
 * This use the native PHP function filter_var which is available in PHP >=
 * 5.2.0 if it is not found in the interpreter this function will sue regular
 * expressions to check whether the email address passed is valid or not.
 *
 * @see http://www.php.net/manual/en/function.filter-var.php
 *
 * @param  string $email The string that will be validated as an email address.
 * @return boolean       TRUE if the email address passed to the function is valid, FALSE if not.
 */
function is_valid_email( $email='' ){
    if( function_exists('filter_var') ){
        return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    } else {
        $pattern = '/^([a-z0-9\+_\-]+)(\.[a-z0-9\+_\-]+)*@([a-z0-9\-]+\.)+[a-z]{2,6}$/ix';
        return (bool) preg_match($pattern, $email);
    }
}

/**
 * Cut a long text to the length specified, and append suspensive points at the end.
 *
 * @param  string  $text   String of characters that will be cut.
 * @param  integer $length Maximum length of the returned string, default is 10.
 * @return string          Short version of the text specified.
 */
function sucuriscan_excerpt( $text='', $length=10 ){
    $text_length = strlen($text);

    if( $text_length > $length ){
        return substr( $text, 0, $length ) . '...';
    }

    return $text;
}

/**
 * Check whether the email notifications will be sent in HTML or Plain/Text.
 *
 * @return boolean Whether the emails will be in HTML or Plain/Text.
 */
function sucuriscan_prettify_mails(){
    return ( sucuriscan_get_option('sucuriscan_prettify_mails') === 'enabled' );
}

/**
 * Check whether the SSL certificates will be verified while executing a HTTP
 * request or not. This is only for customization of the administrator, in fact
 * not verifying the SSL certificates can lead to a "Man in the Middle" attack.
 *
 * @return boolean Whether the SSL certs will be verified while sending a request.
 */
function sucuriscan_verify_ssl_cert(){
    return ( sucuriscan_get_option('sucuriscan_verify_ssl_cert') === 'true' );
}

/**
 * Send a message to a specific email address.
 *
 * @param  string  $email    The email address of the recipient that will receive the message.
 * @param  string  $subject  The reason of the message that will be sent.
 * @param  string  $message  Body of the message that will be sent.
 * @param  array   $data_set Optional parameter to add more information to the notification.
 * @return boolean           Whether the email contents were sent successfully.
 */
function sucuriscan_send_mail( $email='', $subject='', $message='', $data_set=array() ){
    $headers = array();
    $subject = ucwords(strtolower($subject));
    $wp_domain = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : get_option('siteurl');
    $force = FALSE;
    $debug = FALSE;

    // Check whether the mail will be printed in the site instead of sent.
    if(
        isset($data_set['Debug'])
        && $data_set['Debug'] == TRUE
    ){
        $debug = TRUE;
        unset($data_set['Debug']);
    }

    // Check whether the mail will be even if the limit per hour was reached or not.
    if(
        isset($data_set['Force'])
        && $data_set['Force'] == TRUE
    ){
        $force = TRUE;
        unset($data_set['Force']);
    }

    // Check whether the email notifications will be sent in HTML or Plain/Text.
    if( sucuriscan_prettify_mails() ){
        $headers = array( 'Content-type: text/html' );
        $data_set['PrettifyType'] = 'pretty';
    }

    if( !sucuriscan_emails_per_hour_reached() || $force || $debug ){
        $message = sucuriscan_prettify_mail($subject, $message, $data_set);

        if( $debug ){ die($message); }

        $email_sent = wp_mail(
            $email,
            "Sucuri WP Notification: {$wp_domain} - {$subject}",
            $message,
            $headers
        );

        if( $email_sent ){
            $emails_sent_num = (int) sucuriscan_get_option('sucuriscan_emails_sent');
            update_option( 'sucuriscan_emails_sent', $emails_sent_num + 1 );
            update_option( 'sucuriscan_last_email_at', time() );

            return TRUE;
        }
    } else {
        // sucuriscan_error( 'Cant send more emails for the next hour' );
    }

    return FALSE;
}

/**
 * Check whether the maximum quantity of emails per hour was reached.
 *
 * @return boolean Whether the quota emails per hour was reached.
 */
function sucuriscan_emails_per_hour_reached(){
    $max_emails_per_hour = sucuriscan_get_option('sucuriscan_emails_per_hour');

    if( $max_emails_per_hour != 'unlimited' ){
        // Check if we are still in that sixty minutes.
        $current_time = time();
        $last_email_at = sucuriscan_get_option('sucuriscan_last_email_at');
        $diff_time = abs( $current_time - $last_email_at );

        if( $diff_time <= 3600 ){
            // Check if the quantity of emails sent is bigger than the configured.
            $emails_sent = (int) sucuriscan_get_option('sucuriscan_emails_sent');
            $max_emails_per_hour = intval($max_emails_per_hour);

            if( $emails_sent >= $max_emails_per_hour ){
                return TRUE;
            }
        } else {
            // Reset the counter of emails sent.
            update_option( 'sucuriscan_emails_sent', 0 );
        }
    }

    return FALSE;
}

/**
 * Generate a HTML version of the message that will be sent through an email.
 *
 * @param  string $subject  The reason of the message that will be sent.
 * @param  string $message  Body of the message that will be sent.
 * @param  array  $data_set Optional parameter to add more information to the notification.
 * @return string           The message formatted in a HTML template.
 */
function sucuriscan_prettify_mail( $subject='', $message='', $data_set=array() ){
    $prettify_type = isset($data_set['PrettifyType']) ? $data_set['PrettifyType'] : 'simple';
    $template_name = 'notification-' . $prettify_type;
    $remote_addr = sucuriscan_get_remoteaddr();
    $user = wp_get_current_user();
    $display_name = '';

    if(
        $user instanceof WP_User
        && isset($user->user_login)
        && !empty($user->user_login)
    ){
        $display_name = sprintf( 'User: %s (%s)', $user->display_name, $user->user_login );
    }

    $mail_variables = array(
        'TemplateTitle' => 'Sucuri WP Notification',
        'Subject' => $subject,
        'Website' => get_option('siteurl'),
        'RemoteAddress' => $remote_addr,
        'Message' => $message,
        'User' => $display_name,
        'Time' => current_time('mysql'),
    );

    foreach($data_set as $var_key=>$var_value){
        $mail_variables[$var_key] = $var_value;
    }

    return sucuriscan_get_section( $template_name, $mail_variables );
}

/**
 * Prints a HTML alert in the WordPress admin interface.
 *
 * @param  string $type    The type of alert, it can be either Updated or Error.
 * @param  string $message The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_admin_notice($type='updated', $message=''){
    $alert_id = rand(100, 999);
    if( !empty($message) ): ?>
        <div id="sucuriscan-alert-<?php echo $alert_id; ?>" class="<?php echo $type; ?> sucuriscan-alert sucuriscan-alert-<?php echo $type; ?>">
            <a href="javascript:void(0)" class="close" onclick="sucuriscan_alert_close('<?php echo $alert_id; ?>')">&times;</a>
            <p><?php _e($message); ?></p>
        </div>
    <?php endif;
}

/**
 * Prints a HTML alert of type ERROR in the WordPress admin interface.
 *
 * @param  string $error_msg The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_error( $error_msg='' ){
    sucuriscan_admin_notice( 'error', '<b>Sucuri:</b> ' . $error_msg );
}

/**
 * Prints a HTML alert of type INFO in the WordPress admin interface.
 *
 * @param  string $info_msg The message that will be printed in the alert.
 * @return void
 */
function sucuriscan_info( $info_msg='' ){
    sucuriscan_admin_notice( 'updated', '<b>Sucuri:</b> ' . $info_msg );
}

/**
 * Verify the nonce of the previous page after a form submission. If the
 * validation fails the execution of the script will be stopped and a dead page
 * will be printed to the client using the official WordPress method.
 *
 * @return boolean Either TRUE or FALSE if the nonce is valid or not respectively.
 */
function sucuriscan_check_page_nonce(){
    if( !empty($_POST) ){
        $nonce_name = 'sucuriscan_page_nonce';

        if( !isset($_POST[$nonce_name]) || !wp_verify_nonce($_POST[$nonce_name], $nonce_name) ){
            wp_die(__('WordPress Nonce verification failed, try again going back and checking the form.') );

            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Replace all pseudo-variables from a string of characters.
 *
 * @param  string $content The content of a template file which contains pseudo-variables.
 * @param  array  $params  List of pseudo-variables that will be replaced in the template.
 * @return string          The content of the template with the pseudo-variables replated.
 */
function sucuriscan_replace_pseudovars( $content='', $params=array() ){
    if( is_array($params) ){
        foreach( $params as $tpl_key => $tpl_value ){
            $tpl_key = '%%SUCURI.' . $tpl_key . '%%';
            $content = str_replace( $tpl_key, $tpl_value, $content );
        }

        return $content;
    }

    return FALSE;
}

/**
 * Complement the list of pseudo-variables that will be used in the base
 * template files, this will also generate the navigation bar and detect which
 * items in it are selected by the current page.
 *
 * @param  array  $params A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return array          A complementary list of pseudo-variables for the template files.
 */
function sucuriscan_links_and_navbar( $params=array() ){
    $params = is_array($params) ? $params : array();
    $sub_pages = sucuriscan_pages(TRUE);

    $params['Navbar'] = '';
    $params['CurrentPageFunc'] = isset($_GET['page']) ? $_GET['page'] : '';

    foreach( $sub_pages as $sub_page_func => $sub_page_title ){
        $func_parts = explode( '_', $sub_page_func, 2 );

        if( isset($func_parts[1]) ){
            $unique_name = $func_parts[1];
            $pseudo_var = 'URL.' . ucwords($unique_name);
        } else {
            $unique_name = '';
            $pseudo_var = 'URL.Home';
        }

        $params[$pseudo_var] = sucuriscan_get_url($unique_name);

        $navbar_item_css_class = 'nav-tab';

        if( $params['CurrentPageFunc'] == $sub_page_func ){
            $navbar_item_css_class .= chr(32) . 'nav-tab-active';
        }

        $params['Navbar'] .= sprintf(
            '<a class="%s" href="%s">%s</a>' . "\n",
            $navbar_item_css_class,
            $params[$pseudo_var],
            $sub_page_title
        );
    }

    return $params;
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string  $template Filename of the template that will be used to generate the page.
 * @param  array   $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @param  boolean $type     Either page, section or snippet indicating the type of template that will be retrieved.
 * @return string            The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_template( $template='', $params=array(), $type='page' ){
    switch( $type ){
        case 'page': /* no_break */
        case 'section':
            $template_path_pattern = '%s/%s/inc/tpl/%s.html.tpl';
            break;
        case 'snippet':
            $template_path_pattern = '%s/%s/inc/tpl/%s.snippet.tpl';
            break;
    }

    $template_content = '';
    $template_path =  sprintf( $template_path_pattern, WP_PLUGIN_DIR, SUCURISCAN_PLUGIN_FOLDER, $template );
    $params = is_array($params) ? $params : array();

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);

        $current_page = isset($_GET['page']) ? htmlentities($_GET['page']) : '';
        $params['CurrentURL'] = sprintf( '%s/wp-admin/admin.php?page=%s', site_url(), $current_page );
        $params['SucuriURL'] = SUCURI_URL;

        // Replace the global pseudo-variables in the section/snippets templates.
        if(
            $template == 'base'
            && isset($params['PageContent'])
            && preg_match('/%%SUCURI\.(.+)%%/', $params['PageContent'])
        ){
            $params['PageContent'] = sucuriscan_replace_pseudovars( $params['PageContent'], $params );
        }

        $template_content = sucuriscan_replace_pseudovars( $template_content, $params );
    }

    if( $template == 'base' || $type != 'page' ){
        return $template_content;
    }

    return sucuriscan_get_base_template( $template_content, $params );
}

/**
 * Gather and generate the information required globally by all the template files.
 *
 * @param  array $params A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return array         A complementary list of pseudo-variables for the template files.
 */
function sucuriscan_shared_params( $params=array() ){
    $params = is_array($params) ? $params : array();

    // Base parameters, required to render all the pages.
    $params = sucuriscan_links_and_navbar($params);

    // Global parameters, used through out all the pages.
    $params['PageTitle'] = isset($params['PageTitle']) ? '('.$params['PageTitle'].')' : '';
    $params['PageNonce'] = wp_create_nonce('sucuriscan_page_nonce');
    $params['PageStyleClass'] = isset($params['PageStyleClass']) ? $params['PageStyleClass'] : 'base';
    $params['CleanDomain'] = sucuriscan_get_domain();
    $params['AdminEmail'] = sucuriscan_get_site_email();

    return $params;
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $html   The HTML content of a template file with its pseudo-variables parsed.
 * @param  array  $params A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string         The formatted HTML content of the base template.
 */
function sucuriscan_get_base_template( $html='', $params=array() ){
    $params = is_array($params) ? $params : array();

    $params = sucuriscan_shared_params($params);
    $params['PageContent'] = $html;

    return sucuriscan_get_template( 'base', $params );
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template Filename of the template that will be used to generate the page.
 * @param  array  $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string           The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_section($template='', $params=array()){
    $params = sucuriscan_shared_params($params);

    return sucuriscan_get_template( $template, $params, 'section' );
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template Filename of the template that will be used to generate the page.
 * @param  array  $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string           The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_modal($template='', $params=array()){
    $required = array(
        'Title' => 'Lorem ipsum dolor sit amet',
        'CssClass' => '',
        'Content' => '<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
            eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
            veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
            consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
            cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
            proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>',
    );

    if( !empty($template) && $template != 'none' ){
        $params['Content'] = sucuriscan_get_section($template);
    }

    foreach( $required as $param_name => $param_value ){
        if( !isset($params[$param_name]) ){
            $params[$param_name] = $param_value;
        }
    }

    $params = sucuriscan_shared_params($params);

    return sucuriscan_get_template( 'modalwindow', $params, 'section' );
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template Filename of the template that will be used to generate the page.
 * @param  array  $params   A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string           The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriscan_get_snippet($template='', $params=array()){
    return sucuriscan_get_template( $template, $params, 'snippet' );
}

/**
 * Generate an URL pointing to the page indicated in the function and that must
 * be loaded through the administrator panel.
 *
 * @param  string $page Short name of the page that will be generated.
 * @return string       Full string containing the link of the page.
 */
function sucuriscan_get_url($page=''){
    $url_path = admin_url('admin.php?page=sucuriscan');

    if( !empty($page) ){
        $url_path .= '_' . $page;
    }

    return $url_path;
}

/**
 * Retrieve a new set of keys for the WordPress configuration file using the
 * official API provided by WordPress itself.
 *
 * @return array A list of the new set of keys generated by WordPress API.
 */
function sucuriscan_get_new_config_keys(){
    $request = wp_remote_get('https://api.wordpress.org/secret-key/1.1/salt/');

    if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
        if( preg_match_all("/define\('([A-Z_]+)',[ ]+'(.*)'\);/", $request['body'], $match) ){
            $new_keys = array();

            foreach($match[1] as $i=>$value){
                $new_keys[$value] = $match[2][$i];
            }

            return $new_keys;
        }
    }

    return FALSE;
}

/**
 * Modify the WordPress configuration file and change the keys that were defined
 * by a new random-generated list of keys retrieved from the official WordPress
 * API. The result of the operation will be either FALSE in case of error, or an
 * array containing multiple indexes explaining the modification, among them you
 * will find the old and new keys.
 *
 * @return false|array Either FALSE in case of error, or an array with the old and new keys.
 */
function sucuriscan_set_new_config_keys(){
    $new_wpconfig = '';
    $wp_config_path = ABSPATH.'wp-config.php';

    if( file_exists($wp_config_path) ){
        $wp_config_lines = file($wp_config_path);
        $new_keys = sucuriscan_get_new_config_keys();
        $old_keys = array();
        $old_keys_string = $new_keys_string = '';

        foreach($wp_config_lines as $wp_config_line){
            $wp_config_line = str_replace("\n", '', $wp_config_line);

            if( preg_match("/define\('([A-Z_]+)',([ ]+)'(.*)'\);/", $wp_config_line, $match) ){
                $key_name = $match[1];
                if( array_key_exists($key_name, $new_keys) ){
                    $white_spaces = $match[2];
                    $old_keys[$key_name] = $match[3];
                    $wp_config_line = "define('{$key_name}',{$white_spaces}'{$new_keys[$key_name]}');";

                    $old_keys_string .= "define('{$key_name}',{$white_spaces}'{$old_keys[$key_name]}');\n";
                    $new_keys_string .= "{$wp_config_line}\n";
                }
            }

            $new_wpconfig .= "{$wp_config_line}\n";
        }

        $response = array(
            'updated' => is_writable($wp_config_path),
            'old_keys' => $old_keys,
            'old_keys_string' => $old_keys_string,
            'new_keys' => $new_keys,
            'new_keys_string' => $new_keys_string,
            'new_wpconfig' => $new_wpconfig,
        );

        if( $response['updated'] ){
            file_put_contents($wp_config_path, $new_wpconfig, LOCK_EX);
        }
        return $response;
    }
    return FALSE;
}

/**
 * Generate and set a new password for a specific user not in session.
 *
 * @param  integer $user_id The user identifier that will be changed, this must be different than the user in session.
 * @return boolean          Either TRUE or FALSE in case of success or error respectively.
 */
function sucuriscan_new_password($user_id=0){
    $user_id = intval($user_id);
    $current_user = wp_get_current_user();

    if( $user_id>0 && $user_id!=$current_user->ID ){
        $user = get_userdata($user_id);
        $new_password = wp_generate_password(15, TRUE, FALSE);

        $data_set = array( 'User'=>$user->display_name );
        $message = "The password for your user account in the website mentioned has been changed by an administrator,
            this is the new password automatically generated by the system, please update ASAP.<br>
            <div style='display:inline-block;background:#ddd;font-family:monaco,monospace,courier;
            font-size:30px;margin:0;padding:15px;border:1px solid #999'>{$new_password}</div>";
        sucuriscan_send_mail($user->user_email, 'Changed password', $message, $data_set);

        wp_set_password($new_password, $user_id);

        return TRUE;
    }
    return FALSE;
}

/**
 * Retrieve the real ip address of the user in the current request.
 *
 * @return string The real ip address of the user in the current request.
 */
function sucuriscan_get_remoteaddr(){
    $alternatives = array(
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR',
        'SUCURI_RIP',
    );
    foreach($alternatives as $alternative){
        if( !isset($_SERVER[$alternative]) ){ continue; }

        $remote_addr = preg_replace('/[^0-9a-z.,: ]/', '', $_SERVER[$alternative]);
        if($remote_addr) break;
    }

    if( $remote_addr == '::1' ){
        $remote_addr = '127.0.0.1';
    }

    return $remote_addr;
}

/**
 * Retrieve the user-agent from the current request.
 *
 * @return string The user-agent from the current request.
 */
function sucuriscan_get_useragent(){
    if( isset($_SERVER['HTTP_USER_AGENT']) ){
        return esc_attr($_SERVER['HTTP_USER_AGENT']);
    }

    return FALSE;
}

/**
 * Check whether the site is behing the Sucuri CloudProxy network.
 *
 * @return boolean Either TRUE or FALSE if the site is behind CloudProxy.
 */
function sucuriscan_is_behind_cloudproxy(){
    $http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    if( preg_match('/^(.*):([0-9]+)/', $http_host, $match) ){ $http_host = $match[1]; }
    $host_by_name = gethostbyname($http_host);
    $host_by_addr = gethostbyaddr($host_by_name);

    if(
        isset($_SERVER['SUCURIREAL_REMOTE_ADDR'])
        || preg_match('/^cloudproxy([0-9]+)\.sucuri\.net$/', $host_by_addr)
    ){
        return TRUE;
    }

    return FALSE;
}

/**
 * Find and retrieve the current version of Wordpress installed.
 *
 * @return string The version number of Wordpress installed.
 */
function sucuriscan_get_wpversion(){
    $version = get_option('version');
    if( $version ){ return $version; }

    $wp_version_path = ABSPATH . WPINC . '/version.php';
    if( file_exists($wp_version_path) ){
        include($wp_version_path);
        if( isset($wp_version) ){ return $wp_version; }
    }

    return md5_file(ABSPATH . WPINC . '/class-wp.php');
}

/**
 * Find and retrieve the absolute path of the WordPress configuration file.
 *
 * @return string Absolute path of the WordPress configuration file.
 */
function sucuriscan_get_wpconfig_path(){
    $wp_config_path = ABSPATH.'wp-config.php';

    // if wp-config.php doesn't exist/not readable check one directory up
    if( !is_readable($wp_config_path)){
        $wp_config_path = ABSPATH.'/../wp-config.php';
    }

    return $wp_config_path;
}

/**
 * Find and retrieve the absolute path of the main WordPress htaccess file.
 *
 * @return string Absolute path of the main WordPress htaccess file.
 */
function sucuriscan_get_htaccess_path(){
    $base_dirs = array(
        rtrim(ABSPATH, '/'),
        dirname(ABSPATH),
        dirname(dirname(ABSPATH))
    );

    foreach($base_dirs as $base_dir){
        $htaccess_path = sprintf('%s/.htaccess', $base_dir);
        if( file_exists($htaccess_path) ){
            return $htaccess_path;
        }
    }

    return FALSE;
}

/**
 * Get the email address set by the administrator to receive the notifications
 * sent by the plugin, if the email is missing the WordPress email address is
 * chosen by default.
 *
 * @return string The administrator email address.
 */
function sucuriscan_get_site_email(){
    $email = get_option('admin_email');

    if( is_valid_email($email) ){
        return $email;
    }

    return FALSE;
}

/**
 * Get the clean version of the current domain.
 *
 * @return string The domain of the current site.
 */
function sucuriscan_get_domain(){
    $http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $domain_name =  preg_replace( '/^www\./', '', $http_host );

    return $domain_name;
}

/**
 * Generate an user-agent for the HTTP requests.
 *
 * @return string An user-agent for the HTTP requests.
 */
function sucuriscan_user_agent(){
    global $wp_version;

    $user_agent = 'WordPress/' . $wp_version . '; ' . sucuriscan_get_domain();

    return $user_agent;
}

/**
 * Return the time passed since the specified timestamp until now.
 *
 * @param  integer $timestamp The Unix time number of the date/time before now.
 * @return string             The time passed since the timestamp specified.
 */
function sucuriscan_time_ago($timestamp=0){
    if( !is_numeric($timestamp) ){
        $timestamp = strtotime($timestamp);
    }

    $diff = abs( time() - intval($timestamp) );

    if( $diff == 0 ){ return 'just now'; }

    $intervals = array(
        1                => array('year',   31556926),
        $diff < 31556926 => array('month',  2628000),
        $diff < 2629744  => array('week',   604800),
        $diff < 604800   => array('day',    86400),
        $diff < 86400    => array('hour',   3600),
        $diff < 3600     => array('minute', 60),
        $diff < 60       => array('second', 1)
    );

    $value = floor($diff/$intervals[1][1]);
    $time_ago = sprintf(
        '%s %s%s ago',
        $value,
        $intervals[1][0],
        ( $value > 1 ? 's' : '' )
    );

    return $time_ago;
}

/**
 * Convert an string of characters into a valid variable name.
 *
 * @see http://www.php.net/manual/en/language.variables.basics.php
 *
 * @param  string $string A text containing alpha-numeric and special characters.
 * @return string         A valid variable name.
 */
function sucuriscan_str_human2var($string=''){
    $pattern = '/[^a-zA-Z0-9_]/';
    $var_name = preg_replace($pattern, '_', strtolower($string));

    return $var_name;
}

/**
 * Retrieve specific options from the database.
 *
 * Considering the case in which this plugin is installed in a multisite instance
 * of Wordpress, the allowed values for the first parameter of this function will
 * be treated like this:
 *
 * <ul>
 *   <li>all_sucuriscan_options: Will retrieve all the option values created by this plugin in the main site (aka. network),</li>
 *   <li>site_options: Will retrieve all the option values stored in the current site visited by the user (aka. sub-site) excluding the transient options,</li>
 *   <li>sucuriscan_option: Will retrieve one specific option from the network site only if the option starts with the prefix <i>sucuri_<i>.</li>
 * </ul>
 *
 * @param  string $filter_by   Criteria to filter the results, valid values: all_sucuriscan_options, site_options, sucuri_option.
 * @param  string $option_name Optional parameter with the name of the option that will be filtered.
 * @return array               List of options retrieved from the query in the database.
 */
function sucuriscan_get_options_from_db( $filter_by='', $option_name='' ){
    global $wpdb;

    $output = FALSE;
    switch($filter_by){
        case 'all_sucuriscan_options':
            $output = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name LIKE 'sucuriscan%' ORDER BY option_id ASC");
            break;
        case 'site_options':
            $output = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name NOT LIKE '%_transient_%' ORDER BY option_id ASC");
            break;
        case 'sucuriscan_option':
            $row = $wpdb->get_row( $wpdb->prepare("SELECT option_value FROM {$wpdb->base_prefix}options WHERE option_name = %s LIMIT 1", $option_name) );
            if( $row ){ $output = $row->option_value; }
            break;
    }

    return $output;
}

/**
 * Alias function for the method Common::SucuriScan_Get_Options()
 *
 * This function search the specified option in the database, not only the options
 * set by the plugin but all the options set for the site. If the value retrieved
 * is FALSE the method tries to search for a default value.
 *
 * @param  string $option_name Optional parameter that you can use to filter the results to one option.
 * @return string              The value (or default value) of the option specified.
 */
function sucuriscan_get_option( $option_name='' ){
    return sucuriscan_get_options($option_name);
}

/**
 * Retrieve all the options created by this Plugin from the Wordpress database.
 *
 * The function acts as an alias of WP::get_option() and if the returned value
 * is FALSE it tries to search for a default value to complement the information.
 *
 * @param  string $option_name Optional parameter that you can use to filter the results to one option.
 * @return array               Either FALSE or an Array containing all the sucuri options in the database.
 */
function sucuriscan_get_options( $option_name='' ){
    if( !empty($option_name) ){
        return sucuriscan_get_single_option($option_name);
    }

    $settings = array();
    $results = sucuriscan_get_options_from_db('all_sucuriscan_options');
    foreach( $results as $row ){
        $settings[$row->option_name] = $row->option_value;
    }

    return sucuriscan_get_default_options($settings);
}

/**
 * Retrieve a single option from the database.
 *
 * @param  string $option_name Name of the option that will be retrieved.
 * @return string              Value of the option stored in the database, FALSE if not found.
 */
function sucuriscan_get_single_option( $option_name='' ){
    $is_sucuri_option = preg_match('/^sucuriscan_/', $option_name) ? TRUE : FALSE;

    if( sucuriscan_is_multisite() && $is_sucuri_option ){
        $option_value = sucuriscan_get_options_from_db('sucuriscan_option', $option_name);
    }else{
        $option_value = get_option($option_name);
    }

    if( $option_value === FALSE && $is_sucuri_option ){
        $option_value = sucuriscan_get_default_options($option_name);
    }

    return $option_value;
}

/**
 * Retrieve the default values for some specific options.
 *
 * @param  string|array $settings Either an array that will be complemented or a string with the name of the option.
 * @return string|array           The default values for the specified options.
 */
function sucuriscan_get_default_options( $settings='' ){
    $admin_email = get_option('admin_email');
    $default_options = array(
        'sucuriscan_api_key' => FALSE,
        'sucuriscan_account' => $admin_email,
        'sucuriscan_scan_frequency' => 'hourly',
        'sucuriscan_scan_interface' => 'spl',
        'sucuriscan_runtime' => 0,
        'sucuriscan_lastlogin_redirection' => 'enabled',
        'sucuriscan_notify_to' => $admin_email,
        'sucuriscan_emails_sent' => 0,
        'sucuriscan_emails_per_hour' => 5,
        'sucuriscan_last_email_at' => time(),
        'sucuriscan_prettify_mails' => 'enabled',
        'sucuriscan_notify_success_login' => 'enabled',
        'sucuriscan_notify_failed_login' => 'enabled',
        'sucuriscan_notify_post_publication' => 'enabled',
        'sucuriscan_notify_theme_editor' => 'enabled',
        'sucuriscan_maximum_failed_logins' => 30,
        'sucuriscan_ignored_events' => '',
        'sucuriscan_verify_ssl_cert' => 'true',
    );

    if( is_array($settings) ){
        foreach( $default_options as $option_name => $option_value ){
            if( !isset($settings[$option_name]) ){
                $settings[$option_name] = $option_value;
            }
        }
        return $settings;
    }

    if( is_string($settings) ){
        if( isset($default_options[$settings]) ){
            return $default_options[$settings];
        }
    }

    return FALSE;
}

/**
 * Retrieve all the options stored by Wordpress in the database. The options
 * containing the word "transient" are excluded from the results, this function
 * is compatible with multisite instances.
 *
 * @return array All the options stored by Wordpress in the database, except the transient options.
 */
function sucuriscan_get_wp_options(){
    $settings = array();

    $results = sucuriscan_get_options_from_db('site_options');
    foreach( $results as $row ){
        $settings[$row->option_name] = $row->option_value;
    }

    return $settings;
}

/**
 * Check what Wordpress options were changed comparing the values in the database
 * with the values sent through a simple request using a GET or POST method.
 *
 * @param  array  $request The content of the global variable GET or POST considering SERVER[REQUEST_METHOD].
 * @return array           A list of all the options that were changes through this request.
 */
function sucuriscan_what_options_were_changed( $request=array() ){
    $options_changed = array(
        'original' => array(),
        'changed' => array()
    );
    $wp_options = sucuriscan_get_wp_options();

    foreach( $request as $req_name => $req_value ){
        if(
            array_key_exists($req_name, $wp_options)
            && $wp_options[$req_name] != $req_value
        ){
            $options_changed['original'][$req_name] = $wp_options[$req_name];
            $options_changed['changed'][$req_name] = $req_value;
        }
    }
    return $options_changed;
}

/**
 * Get a list of the post types ignored to receive email notifications when the
 * "new site content" hook is triggered.
 *
 * @return array List of ignored posts-types to send notifications.
 */
function sucuriscan_get_ignored_events(){
    $post_types = sucuriscan_get_option('sucuriscan_ignored_events');
    $post_types_arr = @unserialize($post_types);

    if( !is_array($post_types_arr) ){ $post_types_arr = array(); }

    return $post_types_arr;
}

/**
 * Add a new post type to the list of ignored events to send notifications.
 *
 * @param  string  $event_name Unique post-type name.
 * @return boolean             Whether the event was ignored or not.
 */
function sucuriscan_add_ignored_event( $event_name='' ){
    $post_types = get_post_types();

    // Check if the event is a registered post-type.
    if( array_key_exists($event_name, $post_types) ){
        $ignored_events = sucuriscan_get_ignored_events();

        // Check if the event is not ignored already.
        if( !array_key_exists($event_name, $ignored_events) ){
            $ignored_events[$event_name] = time();
            $saved = update_option( 'sucuriscan_ignored_events', serialize($ignored_events) );

            return $saved;
        }
    }

    return FALSE;
}

/**
 * Remove a post type from the list of ignored events to send notifications.
 *
 * @param  string  $event_name Unique post-type name.
 * @return boolean             Whether the event was removed from the list or not.
 */
function sucuriscan_remove_ignored_event( $event_name='' ){
    $ignored_events = sucuriscan_get_ignored_events();

    if( array_key_exists($event_name, $ignored_events) ){
        unset( $ignored_events[$event_name] );
        $saved = update_option( 'sucuriscan_ignored_events', serialize($ignored_events) );

        return $saved;
    }

    return FALSE;
}

/**
 * Check whether an event is being ignored to send notifications or not.
 *
 * @param  string  $event_name Unique post-type name.
 * @return boolean             Whether an event is being ignored or not.
 */
function sucuriscan_is_ignored_event( $event_name='' ){
    $event_name = strtolower($event_name);
    $ignored_events = sucuriscan_get_ignored_events();

    if( array_key_exists($event_name, $ignored_events) ){
        return TRUE;
    }

    return FALSE;
}

if( !function_exists('sucuriscan_plugin_setup_notice') ){
    /**
     * Display a notice message with instructions to continue the setup of the
     * plugin, this includes the generation of the API key and other steps that need
     * to be done to fully activate this plugin.
     *
     * @return void
     */
    function sucuriscan_plugin_setup_notice(){
        if(
            current_user_can('manage_options')
            && !sucuriscan_wordpress_apikey()
            && !isset($_POST['sucuriscan_wordpress_apikey'])
            && !isset($_POST['sucuriscan_recover_api_key'])
        ){
            echo sucuriscan_get_section('setup_notice');
        }
    }

    $sucuriscan_admin_notice_name = sucuriscan_is_multisite() ? 'network_admin_notices' : 'admin_notices';
    add_action( $sucuriscan_admin_notice_name, 'sucuriscan_plugin_setup_notice' );
}

/**
 * Check the plugins directory and retrieve all plugin files with plugin data.
 * This function will also retrieve the URL and name of the repository/page
 * where it is being published at the WordPress plugins market.
 *
 * @return array Key is the plugin file path and the value is an array of the plugin data.
 */
function sucuriscan_get_plugins(){
    $sucuri_cache = new SucuriScanCache('plugindata');
    $cached_data = $sucuri_cache->get( 'plugins', SUCURISCAN_GET_PLUGINS_LIFETIME, 'array' );

    // Return the previously cached results of this function.
    if( $cached_data !== FALSE ){
        return $cached_data;
    }

    // Get the plugin's basic information from WordPress transient data.
    $plugins = get_plugins();
    $pattern = '/^http:\/\/wordpress\.org\/plugins\/(.*)\/$/';
    $wp_market = 'http://wordpress.org/plugins/%s/';

    // Loop through each plugin data and complement its information with more attributes.
    foreach( $plugins as $plugin_path => $plugin_data ){
        // Default values for the plugin extra attributes.
        $repository = '';
        $repository_name = '';
        $is_free_plugin = FALSE;

        // If the plugin's info object has already a plugin_uri.
        if(
            isset($plugin_data['PluginURI'])
            && preg_match($pattern, $plugin_data['PluginURI'], $match)
        ){
            $repository = $match[0];
            $repository_name = $match[1];
            $is_free_plugin = TRUE;
        }

        // Retrieve the WordPress plugin page from the plugin's filename.
        else {
            if( strpos($plugin_path, '/') !== FALSE ){
                $plugin_path_parts = explode('/', $plugin_path, 2);
            } else {
                $plugin_path_parts = explode('.', $plugin_path, 2);
            }

            if( isset($plugin_path_parts[0]) ){
                $possible_repository = sprintf($wp_market, $plugin_path_parts[0]);
                $resp = wp_remote_head($possible_repository);

                if(
                    !is_wp_error($resp)
                    && $resp['response']['code'] == 200
                ){
                    $repository = $possible_repository;
                    $repository_name = $plugin_path_parts[0];
                    $is_free_plugin = TRUE;
                }
            }
        }

        // Complement the plugin's information with these attributes.
        $plugins[$plugin_path]['Repository'] = $repository;
        $plugins[$plugin_path]['RepositoryName'] = $repository_name;
        $plugins[$plugin_path]['IsFreePlugin'] = $is_free_plugin;
        $plugins[$plugin_path]['PluginType'] = ( $is_free_plugin ? 'free' : 'premium' );
        $plugins[$plugin_path]['IsPluginActive'] = FALSE;

        if( is_plugin_active($plugin_path) ){
            $plugins[$plugin_path]['IsPluginActive'] = TRUE;
        }
    }

    // Add the information of the plugins to the file-based cache.
    $sucuri_cache->add( 'plugins', $plugins );

    return $plugins;
}

/**
 * Retrieve plugin installer pages from WordPress Plugins API.
 *
 * It is possible for a plugin to override the Plugin API result with three
 * filters. Assume this is for plugins, which can extend on the Plugin Info to
 * offer more choices. This is very powerful and must be used with care, when
 * overriding the filters.
 *
 * The first filter, 'plugins_api_args', is for the args and gives the action as
 * the second parameter. The hook for 'plugins_api_args' must ensure that an
 * object is returned.
 *
 * The second filter, 'plugins_api', is the result that would be returned.
 *
 * @param  string $repository_name Frienly name of the plugin.
 * @return object                  Object on success, WP_Error on failure.
 */
function sucuriscan_get_remote_plugin_data( $repository_name='' ){
    $repository_base = 'http://api.wordpress.org/plugins/info/1.0/%s/';
    $repository_url = sprintf( $repository_base, $repository_name );
    $resp = wp_remote_get($repository_url);

    if( !is_wp_error($resp) ){
        $plugin_data = @unserialize($resp['body']);

        if( $plugin_data instanceof stdClass ){
            return $plugin_data;
        }
    }

    return FALSE;
}

/**
 * Detect which number in a pagination was clicked.
 *
 * @return integer Page number of the link clicked in a pagination.
 */
function sucuriscan_get_page_number(){
    $page_number = 1;

    // Check if there page was specified in the request.
    if(
        isset($_GET['num'])
        && preg_match('/^[0-9]{1,2}$/', $_GET['num'])
        && $_GET['num'] <= 10
    ){
        $page_number = intval($_GET['num']);
    }

    return $page_number;
}

/**
 * Generate the HTML code to display a pagination.
 *
 * @param  string  $base_url     Base URL for the links before the page number.
 * @param  integer $total_items  Total quantity of items retrieved from a query.
 * @param  integer $max_per_page Maximum number of items that will be shown per page.
 * @return string                HTML code for a pagination generated using the provided data.
 */
function sucuriscan_generate_pagination( $base_url='', $total_items=0, $max_per_page=1 ){
    // Calculate the number of links for the pagination.
    $html_links = '';
    $page_number = sucuriscan_get_page_number();
    $max_pages = ceil($total_items / $max_per_page);

    // Generate the HTML links for the pagination.
    for( $j=1; $j<=$max_pages; $j++ ){
        $link_class = 'sucuriscan-pagination-link';

        if( $page_number == $j ){
            $link_class .= chr(32) . 'sucuriscan-pagination-active';
        }

        $html_links .= sprintf(
            '<li><a href="%s&num=%d" class="%s">%s</a></li>',
            $base_url, $j, $link_class, $j
        );
    }

    return $html_links;
}

/**
 * Display the page with a temporary message explaining the action that will be
 * performed once the hidden form is submitted to retrieve the scanning results
 * from the public SiteCheck API.
 *
 * @return void
 */
function sucuriscan_scanner_page(){
    if(
        sucuriscan_check_page_nonce()
        && isset($_POST['sucuriscan_malware_scan'])
    ){
        sucuriscan_sitecheck_info();
    } else {
        echo sucuriscan_get_template('malwarescan');
    }
}

/**
 * Display the result of site scan made through SiteCheck.
 *
 * @return void
 */
function sucuriscan_sitecheck_info(){
    $sucuri_cache = new SucuriScanCache('sitecheck');
    $scan_results = $sucuri_cache->get( 'scan_results', SUCURISCAN_SITECHECK_LIFETIME, 'array' );
    $clean_domain = sucuriscan_get_domain();
    $display_results = FALSE;

    ob_start();

    if( !$scan_results ){
        $remote_url = 'http://sitecheck.sucuri.net/scanner/?serialized&clear&fromwp&scan='.$clean_domain;
        $scan_results = wp_remote_get($remote_url, array('timeout' => 180));

        if( is_wp_error($scan_results) ){
            sucuriscan_error( $scan_results->get_error_message() );
        }

        elseif( isset($scan_results['body']) ){
            if( preg_match('/^ERROR:(.*)/', $scan_results['body'], $error_m) ){
                sucuriscan_error( 'The site <code>' . $clean_domain . '</code> was not scanned: ' . $error_m[1] );
            }

            else {
                $scan_results = @unserialize($scan_results['body']);
                $display_results = TRUE;

                if( !$sucuri_cache->add( 'scan_results', $scan_results ) ){
                    sucuriscan_error( 'Could not cache the results of the SiteCheck scanning' );
                }
            }
        }
    } else {
        $display_results = TRUE;
        // sucuriscan_info( 'SiteCheck results retrieved from cache.' );
    }
    ?>


    <?php if( $display_results ): ?>

        <?php
        $res = ( is_array($scan_results) ? $scan_results : array() );

        // Check for general warnings, and return the information for Infected/Clean site.
        $malware_warns_exist   = isset($res['MALWARE']['WARN'])   ? TRUE : FALSE;
        $blacklist_warns_exist = isset($res['BLACKLIST']['WARN']) ? TRUE : FALSE;
        $outdated_warns_exist  = isset($res['OUTDATEDSCAN'])      ? TRUE : FALSE;
        $recommendations_exist = isset($res['RECOMMENDATIONS'])   ? TRUE : FALSE;

        // Check whether this WordPress installation needs an update.
        global $wp_version;
        $wordpress_updated = FALSE;
        $updates = function_exists('get_core_updates') ? get_core_updates() : array();

        if( !is_array($updates) || empty($updates) || $updates[0]->response=='latest' ){
            $wordpress_updated = TRUE;
        }

        if( TRUE ){
            // Initialize the CSS classes with default values.
            $sucuriscan_css_blacklist = 'sucuriscan-border-good';
            $sucuriscan_css_malware = 'sucuriscan-border-good';
            $sitecheck_results_tab = '';
            $blacklist_status_tab = '';
            $website_details_tab = '';

            // Generate the CSS classes for the blacklist status.
            if( $blacklist_warns_exist ){
                $sucuriscan_css_blacklist = 'sucuriscan-border-bad';
                $blacklist_status_tab = 'sucuriscan-red-tab';
            }

            // Generate the CSS classes for the SiteCheck scanning results.
            if( $malware_warns_exist ){
                $sucuriscan_css_malware = 'sucuriscan-border-bad';
                $sitecheck_results_tab = 'sucuriscan-red-tab';
            }

            // Generate the CSS classes for the outdated/recommendations panel.
            if( $outdated_warns_exist || $recommendations_exist ){
                $website_details_tab = 'sucuriscan-red-tab';
            }

            $sucuriscan_css_wpupdate = $wordpress_updated ? 'sucuriscan-border-good' : 'sucuriscan-border-bad';
        }
        ?>

        <div id="poststuff">
            <div class="postbox sucuriscan-border sucuriscan-border-info sucuriscan-malwarescan-message">
                <h3>SiteCheck Scanner</h3>

                <div class="inside">
                    <p>
                        If your site was recently hacked, you can see which files were modified
                        recently, to assist with any investigation.
                    </p>
                </div>
            </div>
        </div>


        <div class="sucuriscan-tabs">


            <ul>
                <li class="<?php _e($sitecheck_results_tab) ?>">
                    <a href="#" data-tabname="sitecheck-results">Remote Scanner Results</a>
                </li>
                <li class="<?php _e($website_details_tab) ?>">
                    <a href="#" data-tabname="website-details">Website Details</a>
                </li>
                <li>
                    <a href="#" data-tabname="website-links">IFrames / Links / Scripts</a>
                </li>
                <li class="<?php _e($blacklist_status_tab) ?>">
                    <a href="#" data-tabname="blacklist-status">Blacklist Status</a>
                </li>
                <li>
                    <a href="#" data-tabname="modified-files">Modified Files</a>
                </li>
            </ul>


            <div class="sucuriscan-tab-containers">


                <div id="sucuriscan-sitecheck-results">
                    <div id="poststuff">
                        <div class="postbox sucuriscan-border <?php _e($sucuriscan_css_malware) ?>">
                            <h3>
                                <?php if( $malware_warns_exist ): ?>
                                    Site compromised (malware was identified)
                                <?php else: ?>
                                    Site clean (no malware was identified)
                                <?php endif; ?>
                            </h3>

                            <div class="inside">

                                <?php if( !$malware_warns_exist ): ?>
                                    <p>
                                        <span><strong>Malware:</strong> Clean.</span><br>
                                        <span><strong>Malicious javascript:</strong> Clean.</span><br>
                                        <span><strong>Malicious iframes:</strong> Clean.</span><br>
                                        <span><strong>Suspicious redirections (htaccess):</strong> Clean.</span><br>
                                        <span><strong>Blackhat SEO Spam:</strong> Clean.</span><br>
                                        <span><strong>Anomaly detection:</strong> Clean.</span>
                                    </p>
                                <?php else: ?>
                                    <ul>
                                        <?php
                                        foreach( $res['MALWARE']['WARN'] as $malres ){
                                            if( !is_array($malres) ){
                                                echo '<li>' . htmlspecialchars($malres) . '</li>';
                                            } else {
                                                $mwdetails = explode("\n", htmlspecialchars($malres[1]));
                                                $mw_name_link = isset($mwdetails[0]) ? substr($mwdetails[0], 1) : '';

                                                if( preg_match('/(.*)\. Details: (.*)/', $mw_name_link, $mw_match) ){
                                                    $mw_name_link = sprintf(
                                                        '%s. Details: <a href="%s" target="_blank">%s</a>',
                                                        $mw_match[1], $mw_match[2], $mw_match[2]
                                                    );
                                                }

                                                echo '<li>'. htmlspecialchars($malres[0]) . "\n<br>" . $mw_name_link . "</li>\n";
                                            }
                                        }
                                        ?>
                                    </ul>
                                <?php endif; ?>

                                <p>
                                    <i>
                                        More details here: <a href="http://sitecheck.sucuri.net/results/<?php _e($clean_domain); ?>"
                                        target="_blank">http://sitecheck.sucuri.net/results/<?php _e($clean_domain); ?></a>
                                    </i>
                                </p>

                                <hr />

                                <p>
                                    <i>
                                        If our free scanner did not detect any issue, you may have a more complicated
                                        and hidden problem. You can <a href="http://sucuri.net/signup" target="_blank">
                                        sign up</a> with Sucuri for a complete and in depth scan+cleanup (not included
                                        in the free checks).
                                    </i>
                                </p>

                            </div>
                        </div>
                    </div>
                </div>


                <div id="sucuriscan-website-details">
                    <table class="wp-list-table widefat sucuriscan-table sucuriscan-scanner-details">
                        <thead>
                            <tr>
                                <th colspan="2" class="thead-with-button">
                                    <span>System Information</span>
                                    <?php if( !$wordpress_updated ): ?>
                                        <a href="<?php echo admin_url('update-core.php'); ?>" class="button button-primary thead-topright-action">
                                            Update to <?php _e($updates[0]->version) ?>
                                        </a>
                                    <?php endif; ?>
                                </th>
                            </tr>
                        </thead>

                        <tbody>
                            <!-- List of generic information from the site. -->
                            <?php
                            $possible_keys = array(
                                'DOMAIN' => 'Domain Scanned',
                                'IP' => 'Site IP Address',
                                'HOSTING' => 'Hosting Company',
                                'CMS' => 'CMS Found',
                            );
                            $possible_url_keys = array(
                                'IFRAME' => 'List of iframes found',
                                'JSEXTERNAL' => 'List of external scripts included',
                                'JSLOCAL' => 'List of scripts included',
                                'URL' => 'List of links found',
                            );
                            ?>

                            <?php foreach( $possible_keys as $result_key=>$result_title ): ?>
                                <?php if( isset($res['SCAN'][$result_key]) ): ?>
                                    <?php $result_value = implode(', ', $res['SCAN'][$result_key]); ?>
                                    <tr>
                                        <td><?php _e($result_title) ?></td>
                                        <td><span class="sucuriscan-monospace"><?php _e($result_value) ?></span></td>
                                    </tr>
                                <?php endif; ?>
                            <?php endforeach; ?>

                            <tr>
                                <td>WordPress Version</td>
                                <td><span class="sucuriscan-monospace"><?php _e($wp_version) ?></span></td>
                            </tr>
                            <tr>
                                <td>PHP Version</td>
                                <td><span class="sucuriscan-monospace"><?php _e(phpversion()) ?></span></td>
                            </tr>

                            <!-- List of application details from the site. -->
                            <tr>
                                <th colspan="2">Web application details</th>
                            </tr>
                            <?php foreach( $res['WEBAPP'] as $webapp_key=>$webapp_details ): ?>
                                <?php if( is_array($webapp_details) ): ?>
                                    <?php foreach( $webapp_details as $i=>$details ): ?>
                                        <?php if( is_array($details) ){ $details = isset($details[0]) ? $details[0] : ''; } ?>
                                        <tr>
                                            <td colspan="2">
                                                <span class="sucuriscan-monospace"><?php _e($details) ?></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            <?php endforeach; ?>

                            <?php foreach( $res['SYSTEM']['NOTICE'] as $j=>$notice ): ?>
                                <?php if( is_array($notice) ){ $notice = implode(', ', $notice); } ?>
                                <tr>
                                    <td colspan="2">
                                        <span class="sucuriscan-monospace"><?php _e($notice) ?></span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>

                            <!-- Possible recommendations or outdated software on the site. -->
                            <?php if( $outdated_warns_exist || $recommendations_exist ): ?>
                                <tr>
                                    <th colspan="2">Recommendations for the site</th>
                                </tr>
                            <?php endif; ?>

                            <!-- Possible outdated software on the site. -->
                            <?php if( $outdated_warns_exist ): ?>
                                <?php foreach( $res['OUTDATEDSCAN'] as $outdated ): ?>
                                    <?php if( count($outdated) >= 3 ): ?>
                                        <tr>
                                            <td colspan="2" class="sucuriscan-border-bad">
                                                <strong><?php _e($outdated[0]) ?></strong>
                                                <em>(<?php _e($outdated[2]) ?>)</em>
                                                <span><?php _e($outdated[1]) ?></span>
                                            </td>
                                        </tr>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            <?php endif; ?>

                            <!-- Possible recommendations for the site. -->
                            <?php if( $recommendations_exist ): ?>
                                <?php foreach( $res['RECOMMENDATIONS'] as $recommendation ): ?>
                                    <?php if( count($recommendation) >= 3 ): ?>
                                        <tr>
                                            <td colspan="2" class="sucuriscan-border-bad">
                                                <?php printf(
                                                    '<strong>%s</strong><br><span>%s</span><br><a href="%s" target="_blank">%s</a>',
                                                    $recommendation[0],
                                                    $recommendation[1],
                                                    $recommendation[2],
                                                    $recommendation[2]
                                                ); ?>
                                            </td>
                                        </tr>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>


                <div id="sucuriscan-website-links">
                    <table class="wp-list-table widefat sucuriscan-table sucuriscan-scanner-links">
                        <tbody>
                            <?php foreach( $possible_url_keys as $result_url_key=>$result_url_title ): ?>

                                <?php if( isset($res['LINKS'][$result_url_key]) ): ?>
                                    <tr>
                                        <th colspan="2">
                                            <?php printf(
                                                '%s (%d found)',
                                                __($result_url_title),
                                                count($res['LINKS'][$result_url_key])
                                            ) ?>
                                        </th>
                                    </tr>

                                    <?php foreach( $res['LINKS'][$result_url_key] as $url_path ): ?>
                                        <tr>
                                            <td colspan="2">
                                                <span class="sucuriscan-monospace sucuriscan-wraptext"><?php _e($url_path) ?></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>

                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>


                <div id="sucuriscan-blacklist-status">
                    <div id="poststuff">
                        <div class="postbox sucuriscan-border <?php _e($sucuriscan_css_blacklist) ?>">
                            <h3>
                                <?php if( $blacklist_warns_exist ): ?>
                                    Site blacklisted
                                <?php else: ?>
                                    Site blacklist-free
                                <?php endif; ?>
                            </h3>

                            <div class="inside">
                                <ul>
                                    <?php
                                    foreach(array(
                                        'INFO' => 'CLEAN',
                                        'WARN' => 'WARNING'
                                    ) as $type => $group_title){
                                        if( isset($res['BLACKLIST'][$type]) ){
                                            foreach( $res['BLACKLIST'][$type] as $blres ){
                                                $report_site = htmlspecialchars($blres[0]);
                                                $report_url = htmlspecialchars($blres[1]);
                                                printf(
                                                    '<li><b>%s:</b> %s.<br>Details at <a href="%s" target="_blank">%s</a></li>',
                                                    $group_title, $report_site, $report_url, $report_url
                                                );
                                            }
                                        }
                                    }
                                    ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>


                <div id="sucuriscan-modified-files">
                    <?php echo sucuriscan_modified_files(); ?>
                </div>


            </div>
        </div>

        <?php if( $malware_warns_exist || $blacklist_warns_exist ): ?>
            <a href="http://sucuri.net/signup/" target="_blank" class="button button-primary button-hero sucuriscan-cleanup-btn">
                Get your site protected with Sucuri
            </a>
        <?php endif; ?>

    <?php endif; ?>


    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_base_template($_html, array(
        'PageTitle' => 'Malware Scan',
        'PageContent' => $_html,
        'PageStyleClass' => 'scanner-results',
    ));
    return;
}

/**
 * Retrieves a URL using a changeable HTTP method, returning results in an
 * array. Results include HTTP headers and content.
 *
 * @see http://codex.wordpress.org/Function_Reference/wp_remote_post
 * @see http://codex.wordpress.org/Function_Reference/wp_remote_get
 *
 * @param  string $url    The target URL where the request will be sent.
 * @param  string $method HTTP method that will be used to send the request.
 * @param  array  $params Parameters for the request defined in an associative array of key-value.
 * @param  array  $args   Request arguments like the timeout, redirections, headers, cookies, etc.
 * @return array          Array of results including HTTP headers or WP_Error if the request failed.
 */
function sucuriscan_api_call( $url='', $method='GET', $params=array(), $args=array() ){
    if( !$url ){ return FALSE; }

    $req_args = array(
        'method' => $method,
        'timeout' => 90,
        'redirection' => 2,
        'httpversion' => '1.0',
        'user-agent' => sucuriscan_user_agent(),
        'blocking' => TRUE,
        'headers' => array(),
        'cookies' => array(),
        'compress' => FALSE,
        'decompress' => FALSE,
        'sslverify' => sucuriscan_verify_ssl_cert(),
    );

    // Update the request arguments with the values passed tot he function.
    foreach( $args as $arg_name => $arg_value ){
        if( array_key_exists($arg_name, $req_args) ){
            $req_args[$arg_name] = $arg_value;
        }
    }

    if( $method == 'GET' ){
        $url = sprintf( '%s?%s', $url, http_build_query($params) );
        $response = wp_remote_get( $url, $req_args );
    }

    elseif( $method == 'POST' ){
        $req_args['body'] = $params;
        $response = wp_remote_post( $url, $req_args );
    }

    if( isset($response) ){
        if( is_wp_error($response) ){
            sucuriscan_error(sprintf(
                'Something went wrong with an API call (%s action): %s',
                ( isset($params['a']) ? $params['a'] : 'unknown' ),
                $response->get_error_message()
            ));
        } else {
            $response['body_raw'] = $response['body'];

            if(
                isset($response['headers']['content-type'])
                && $response['headers']['content-type'] = 'application/json'
            ){
                $response['body'] = json_decode($response['body_raw']);
            }

            return $response;
        }
    } else {
        sucuriscan_error( 'HTTP method not allowed: ' . $method );
    }

    return FALSE;
}

/**
 * Store the API key locally.
 *
 * @param  string  $api_key  An unique string of characters to identify this installation.
 * @param  boolean $validate Whether the format of the key should be validated before store it.
 * @return boolean           Either TRUE or FALSE if the key was saved successfully or not respectively.
 */
function sucuriscan_set_api_key( $api_key='', $validate=FALSE ){
    if( $validate ){
        if( !preg_match('/^([a-z0-9]{32})$/', $api_key) ){
            sucuriscan_error( 'Invalid API key format' );
            return FALSE;
        }
    }

    if( !empty($api_key) ){
        sucuriscan_notify_event( 'plugin_change', 'API key updated successfully: ' . $api_key );
    }

    return (bool) update_option( 'sucuriscan_api_key', $api_key );
}

/**
 * Retrieve the API key from the local storage.
 *
 * @return string|boolean The API key or FALSE if it does not exists.
 */
function sucuriscan_wordpress_apikey(){
    $api_key = sucuriscan_get_option('sucuriscan_api_key');

    if( $api_key && strlen($api_key) > 10 ){
        return $api_key;
    }

    return FALSE;
}

/**
 * Check whether the CloudProxy API key is valid or not.
 *
 * @param  string  $api_key      The CloudProxy API key.
 * @param  boolean $return_match Whether the parts of the API key must be returned or not.
 * @return boolean               TRUE if the API key specified is valid, FALSE otherwise.
 */
function sucuriscan_valid_cloudproxy_apikey( $api_key='', $return_match=FALSE ){
    $pattern = '/^([a-z0-9]{32})\/([a-z0-9]{32})$/';

    if( $api_key && preg_match($pattern, $api_key, $match) ){
        if( $return_match ){ return $match; }

        return TRUE;
    }

    return FALSE;
}

/**
 * Check and return the API key for the plugin.
 *
 * In this plugin the key is a pair of two strings concatenated by a single
 * slash, the first part of it is in fact the key and the second part is the
 * unique identifier of the site in the remote server.
 *
 * @return array|boolean FALSE if the key is invalid or not present, an array otherwise.
 */
function sucuriscan_cloudproxy_apikey(){
    $option_name = 'sucuriscan_cloudproxy_apikey';
    $api_key = sucuriscan_get_option($option_name);

    // Check if the cloudproxy-waf plugin was previously installed.
    if( !$api_key ){
        $api_key = sucuriscan_get_option('sucuriwaf_apikey');

        if( $api_key ){
            update_option( $option_name, $api_key );
            delete_option('sucuriwaf_apikey');
        }
    }

    // Check the validity of the API key.
    $match = sucuriscan_valid_cloudproxy_apikey( $api_key, TRUE );

    if( $match ){
        return array(
            'string' => $match[1].'/'.$match[2],
            'k' => $match[1],
            's' => $match[2]
        );
    }

    return FALSE;
}

/**
 * Call an action from the remote API interface of our WordPress service.
 *
 * @param  string  $method       HTTP method that will be used to send the request.
 * @param  array   $params       Parameters for the request defined in an associative array of key-value.
 * @param  boolean $send_api_key Whether the API key should be added to the request parameters or not.
 * @param  array   $args         Request arguments like the timeout, redirections, headers, cookies, etc.
 * @return array                 Array of results including HTTP headers or WP_Error if the request failed.
 */
function sucuriscan_api_call_wordpress( $method='GET', $params=array(), $send_api_key=TRUE, $args=array() ){
    $url = SUCURISCAN_API;
    $params[SUCURISCAN_API_VERSION] = 1;
    $params['p'] = 'wordpress';

    if( $send_api_key ){
        $api_key = sucuriscan_wordpress_apikey();

        if( !$api_key ){ return FALSE; }

        $params['k'] = $api_key;
    }

    $response = sucuriscan_api_call( $url, $method, $params, $args );

    return $response;
}

/**
 * Call an action from the remote API interface of our CloudProxy service.
 *
 * @param  string $method HTTP method that will be used to send the request.
 * @param  array  $params Parameters for the request defined in an associative array of key-value.
 * @return array          Array of results including HTTP headers or WP_Error if the request failed.
 */
function sucuriscan_api_call_cloudproxy( $method='GET', $params=array() ){
    $send_request = FALSE;

    if( isset($params['k']) && isset($params['s']) ){
        $send_request = TRUE;
    } else {
        $api_key = sucuriscan_cloudproxy_apikey();

        if( $api_key ){
            $send_request = TRUE;
            $params['k'] = $api_key['k'];
            $params['s'] = $api_key['s'];
        }
    }

    if( $send_request ){
        $url = SUCURISCAN_CLOUDPROXY_API;
        $params[SUCURISCAN_CLOUDPROXY_API_VERSION] = 1;

        $response = sucuriscan_api_call( $url, $method, $params );

        return $response;
    }

    return FALSE;
}

/**
 * Determine whether an API response was successful or not checking the expected
 * generic variables and types, in case of an error a notification will appears
 * in the administrator panel explaining the result of the operation.
 *
 * @param  array   $response Array of results including HTTP headers or WP_Error if the request failed.
 * @return boolean           Either TRUE or FALSE in case of success or failure of the API response (respectively).
 */
function sucuriscan_handle_response( $response=array() ){
    if( $response ){
        if( $response['body'] instanceof stdClass ){
            if( isset($response['body']->status) ){
                if( $response['body']->status == 1 ){
                    return TRUE;
                } else {
                    sucuriscan_error( ucwords($response['body']->action) . ': ' . $response['body']->messages[0] );
                }
            } else {
                sucuriscan_error( 'Could not determine the status of an API call.' );
            }
        } else {
            sucuriscan_error( 'Unknown API content-type, it was not a JSON-encoded response.' );
        }
    }

    return FALSE;
}

/**
 * Send a request to the API to register this site.
 *
 * @return boolean TRUE if the API key was generated, FALSE otherwise.
 */
function sucuriscan_register_site(){
    $response = sucuriscan_api_call_wordpress( 'POST', array(
        'e' => sucuriscan_get_site_email(),
        's' => sucuriscan_get_domain(),
        'a' => 'register_site',
    ), FALSE );

    if( sucuriscan_handle_response($response) ){
        sucuriscan_set_api_key( $response['body']->output->api_key );
        sucuriscan_create_scheduled_task();
        sucuriscan_notify_event( 'plugin_change', 'Site registered and API key generated' );
        sucuriscan_info( 'The API key for your site was successfully generated and saved.');

        return TRUE;
    }

    return FALSE;
}

/**
 * Send a request to recover a previously registered API key.
 *
 * @return boolean TRUE if the API key was sent to the administrator email, FALSE otherwise.
 */
function sucuriscan_recover_api_key(){
    $clean_domain = sucuriscan_get_domain();

    $response = sucuriscan_api_call_wordpress( 'GET', array(
        'e' => sucuriscan_get_site_email(),
        's' => $clean_domain,
        'a' => 'recover_key',
    ), FALSE );

    if( sucuriscan_handle_response($response) ){
        sucuriscan_notify_event( 'plugin_change', 'API key recovered for domain: ' . $clean_domain );
        sucuriscan_info( $response['body']->output->message );

        return TRUE;
    }

    return FALSE;
}

/**
 * Send a request to the API to store and analyze the events of the site. An
 * event can be anything from a simple request, an internal modification of the
 * settings or files in the administrator panel, or a notification generated by
 * this plugin.
 *
 * @param  string  $event The information gathered through out the normal functioning of the site.
 * @return boolean        TRUE if the event was logged in the monitoring service, FALSE otherwise.
 */
function sucuriscan_send_log( $event='' ){
    if( !empty($event) ){
        $response = sucuriscan_api_call_wordpress( 'POST', array(
            'a' => 'send_log',
            'm' => $event,
        ), TRUE, array( 'timeout' => 20 ) );

        if( sucuriscan_handle_response($response) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Retrieve the event logs registered by the API service.
 *
 * @param  integer $lines How many lines from the log file will be retrieved.
 * @return string         The response of the API service.
 */
function sucuriscan_get_logs( $lines=50 ){
    $response = sucuriscan_api_call_wordpress( 'GET', array(
        'a' => 'get_logs',
        'l' => $lines,
    ) );

    if( sucuriscan_handle_response($response) ){
        $response['body']->output_data = array();
        $log_pattern = '/^([0-9-: ]+) (.*) : (.*)/';
        $extra_pattern = '/(.+ \(multiple entries\):) (.+)/';

        foreach( $response['body']->output as $log ){
            if( preg_match($log_pattern, $log, $log_match) ){
                $log_data = array(
                    'datetime' => $log_match[1],
                    'timestamp' => strtotime($log_match[1]),
                    'account' => $log_match[2],
                    'message' => $log_match[3],
                    'extra' => FALSE,
                    'extra_total' => 0,
                );

                $log_data['message'] = str_replace( ', new size', '; new size', $log_data['message'] );

                if( preg_match($extra_pattern, $log_data['message'], $log_extra) ){
                    $log_data['message'] = $log_extra[1];
                    $log_data['extra'] = explode(',', $log_extra[2]);
                    $log_data['extra_total'] = count($log_data['extra']);
                }

                $response['body']->output_data[] = $log_data;
            }
        }

        return $response['body'];
    }

    return FALSE;
}

/**
 * Send a request to the API to store and analyze the file's hashes of the site.
 * This will be the core of the monitoring tools and will enhance the
 * information of the audit logs alerting the administrator of suspicious
 * changes in the system.
 *
 * @param  string  $hashes The information gathered after the scanning of the site's files.
 * @return boolean         TRUE if the hashes were stored, FALSE otherwise.
 */
function sucuriscan_send_hashes( $hashes='' ){
    if( !empty($hashes) ){
        $response = sucuriscan_api_call_wordpress( 'POST', array(
            'a' => 'send_hashes',
            'h' => $hashes,
        ) );

        if( sucuriscan_handle_response($response) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Checks last time we ran to avoid running twice (or too often).
 *
 * @param  integer $runtime    When the filesystem scan must be scheduled to run.
 * @param  boolean $force_scan Whether the filesystem scan was forced by an administrator user or not.
 * @return boolean             Either TRUE or FALSE representing the success or fail of the operation respectively.
 */
function sucuriscan_verify_run( $runtime=0, $force_scan=FALSE ){
    $runtime_name = 'sucuriscan_runtime';
    $last_run = sucuriscan_get_option($runtime_name);
    $current_time = time();

    if( $last_run && !$force_scan ){
        $runtime_diff = $current_time - $runtime;

        if( $last_run >= $runtime_diff ){
            return FALSE;
        }
    }

    update_option( $runtime_name, $current_time );
    return TRUE;
}

/**
 * Check whether the current WordPress version must be reported to the API
 * service or not, this is to avoid duplicated information in the audit logs.
 *
 * @return boolean TRUE if the current WordPress version must be reported, FALSE otherwise.
 */
function sucuriscan_report_wpversion(){
    $option_name = 'sucuriscan_wp_version';
    $reported_version = sucuriscan_get_option($option_name);
    $wp_version = sucuriscan_get_wpversion();

    if( $reported_version != $wp_version ){
        sucuriscan_send_log( 'WordPress version: ' . $wp_version );
        update_option( $option_name, $wp_version );

        return TRUE;
    }

    return FALSE;
}

/**
 * Schedule the task to run the first filesystem scan.
 *
 * @return void
 */
function sucuriscan_create_scheduled_task(){
    $task_name = 'sucuriscan_scheduled_scan';

    if( !wp_next_scheduled($task_name) ){
        wp_schedule_event( time() + 10, 'twicedaily', $task_name );
    }

    wp_schedule_single_event( time() + 300, $task_name );
    sucuriscan_info( 'The first filesystem scan was scheduled.' );
}

/**
 * Gather all the checksums (aka. file hashes) of this site, send them, and
 * analyze them using the Sucuri Monitoring service, this will generate the
 * audit logs for this site and be part of the integrity checks.
 *
 * @param  boolean $force_scan Whether the filesystem scan was forced by an administrator user or not.
 * @return boolean             TRUE if the filesystem scan was successful, FALSE otherwise.
 */
function sucuriscan_filesystem_scan( $force_scan=FALSE ){
    $minimum_runtime = SUCURISCAN_MINIMUM_RUNTIME;

    if(
        sucuriscan_wordpress_apikey()
        && class_exists('SucuriScanFileInfo')
        && sucuriscan_verify_run( $minimum_runtime, $force_scan )
    ){
        sucuriscan_report_wpversion();

        $sucuri_fileinfo = new SucuriScanFileInfo();
        $scan_interface = sucuriscan_get_option('sucuriscan_scan_interface');
        $signatures = $sucuri_fileinfo->get_directory_tree_md5(ABSPATH, $scan_interface);

        if( $signatures ){
            $hashes_sent = sucuriscan_send_hashes( $signatures );

            if( $hashes_sent ){
                sucuriscan_info( 'Successful filesystem scan' );
                return TRUE;
            } else {
                sucuriscan_error( 'The file hashes could not be stored.' );
            }
        } else {
            sucuriscan_error( 'The file hashes could not be retrieved, the filesystem scan failed.' );
        }
    }

    return FALSE;
}

/**
 * Generates an audit event log (to be sent later).
 *
 * @param  integer $severity Importance of the event that will be reported, values from one to five.
 * @param  string  $location In which part of the system was the event triggered.
 * @param  string  $message  The explanation of the event.
 * @return boolean           TRUE if the event was logged in the monitoring service, FALSE otherwise.
 */
function sucuriscan_report_event( $severity=0, $location='', $message='' ){
    $user = wp_get_current_user();
    $username = FALSE;
    $current_time = date( 'Y-m-d H:i:s' );
    $remote_ip = sucuriscan_get_remoteaddr();

    // Fixing severity value.
    $severity = (int) $severity;
    if( $severity > 0 ){ $severity = 1; }
    elseif( $severity > 5 ){ $severity = 5; }

    // Identify current user in session.
    if(
        $user instanceof WP_User
        && isset($user->user_login)
        && !empty($user->user_login)
    ){
        if( $user->user_login != $user->display_name ){
            $username = sprintf( ' %s (%s),', $user->display_name, $user->user_login );
        } else {
            $username = sprintf( ' %s,', $user->user_login );
        }
    }

    // Convert the severity number into a readable string.
    switch( $severity ){
        case 0:  $severity_name = 'Debug';    break;
        case 1:  $severity_name = 'Notice';   break;
        case 2:  $severity_name = 'Info';     break;
        case 3:  $severity_name = 'Warning';  break;
        case 4:  $severity_name = 'Error';    break;
        case 5:  $severity_name = 'Critical'; break;
        default: $severity_name = 'Info';     break;
    }

    $message = str_replace( array("\n", "\r"), array('', ''), $message );
    $event_message = sprintf(
        '%s:%s %s; %s',
        $severity_name,
        $username,
        $remote_ip,
        $message
    );

    return sucuriscan_send_log($event_message);
}

/**
 * Send a notification to the administrator of the specified events, only if
 * the administrator accepted to receive alerts for this type of events.
 *
 * @param  string $event   The name of the event that was triggered.
 * @param  string $content Body of the email that will be sent to the administrator.
 * @return void
 */
function sucuriscan_notify_event( $event='', $content='' ){
    $event_name = 'sucuriscan_notify_' . $event;
    $notify = sucuriscan_get_option($event_name);
    $email = sucuriscan_get_option('sucuriscan_notify_to');
    $email_params = array();

    if( $notify == 'enabled' ){
        if( $event == 'post_publication' ){
            $event = 'post_update';
        }

        elseif( $event == 'failed_login' ){
            $content .= '<br><br><em>Explanation: Someone failed to login to your site. If you
                are getting too many of these messages, it is likely your site is under a brute
                force attack. You can disable the notifications for failed logins from
                <a href="' . sucuriscan_get_url('settings') . '" target="_blank">here</a>.
                More details at <a href="http://kb.sucuri.net/definitions/attacks/brute-force/password-guessing"
                target="_blank">Password Guessing Brute Force Attacks</a>.</em>';
        }

        // Send a notification even if the limit of emails per hour was reached.
        elseif( $event == 'bruteforce_attack' ){
            $email_params['Force'] = TRUE;
        }

        $title = sprintf( 'Sucuri notification (%s)', str_replace('_', chr(32), $event) );
        $mail_sent = sucuriscan_send_mail( $email, $title, $content, $email_params );

        return $mail_sent;
    }

    return FALSE;
}

/**
 * Retrieve the public settings of the account associated with the API keys
 * registered by the administrator of the site. This function will send a HTTP
 * request to the remote API service and process its response, when successful
 * it will return an array/object containing the public attributes of the site.
 *
 * @param  boolean $api_key The CloudProxy API key.
 * @return array            A hash with the settings of a CloudProxy account.
 */
function sucuriscan_cloudproxy_settings( $api_key=FALSE ){
    $params = array( 'a' => 'show_settings' );

    if( $api_key ){
        $params = array_merge( $params, $api_key );
    }

    $response = sucuriscan_api_call_cloudproxy( 'GET', $params );

    if( sucuriscan_handle_response($response) ){
        return $response['body']->output;
    }

    return FALSE;
}

/**
 * Flush the cache of the site(s) associated with the API key.
 *
 * @param  boolean $api_key The CloudProxy API key.
 * @return string           Message explaining the result of the operation.
 */
function sucuriscan_cloudproxy_clear_cache( $api_key=FALSE ){
    $params = array( 'a' => 'clear_cache' );

    if( $api_key ){
        $params = array_merge( $params, $api_key );
    }

    $response = sucuriscan_api_call_cloudproxy( 'GET', $params );

    if( sucuriscan_handle_response($response) ){
        return $response['body'];
    }

    return FALSE;
}

/**
 * Retrieve the audit logs of the account associated with the API keys
 * registered b the administrator of the site. This function will send a HTTP
 * request to the remote API service and process its response, when successful
 * it will return an array/object containing a list of requests blocked by our
 * CloudProxy.
 *
 * By default the logs that will be retrieved are from today, if you need to see
 * the logs of previous days you will need to add a new parameter to the request
 * URL named "date" with format yyyy-mm-dd.
 *
 * @param  boolean $api_key The CloudProxy API key.
 * @param  string  $date    An optional date to filter the result to a specific timespan: yyyy-mm-dd.
 * @return array            A list of objects with the detailed version of each request blocked by our service.
 */
function sucuriscan_cloudproxy_logs( $api_key=FALSE, $date='' ){
    $params = array(
        'a' => 'audit_trails',
        'date' => date('Y-m-d'),
    );

    if( preg_match('/^([0-9]{4})\-([0-9]{2})\-([0-9]{2})$/', $date) ){
        $params['date'] = $date;
    }

    if( $api_key ){
        $params = array_merge( $params, $api_key );
    }

    $response = sucuriscan_api_call_cloudproxy( 'GET', $params );

    if( sucuriscan_handle_response($response) ){
        return $response['body']->output;
    }

    return FALSE;
}

$sucuriscan_hooks = array(
    'add_attachment',
    'create_category',
    'delete_post',
    'private_to_published',
    'publish_page',
    'publish_post',
    'publish_phone',
    'xmlrpc_publish_post',
    'add_link',
    'switch_theme',
    'delete_user',
    'retrieve_password',
    'user_register',
    'wp_login',
    'wp_login_failed',
    'login_form_resetpass',
);

/**
 * Send to Sucuri servers an alert advising that an attachment was added to a post.
 *
 * @param  integer $id The post identifier.
 * @return void
 */
function sucuriscan_hook_add_attachment( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );
    $title = ( $data ? $data->post_title : 'Unknown' );

    $message = 'Media file added #'.$id.' ('.$title.')';
    sucuriscan_report_event( 1, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that a category was created.
 *
 * @param  integer $id The identifier of the category created.
 * @return void
 */
function sucuriscan_hook_create_category( $id=0 ){
    $title = ( is_int($id) ? get_cat_name($id) : 'Unknown' );

    $message = 'Category created #'.$id.' ('.$title.')';
    sucuriscan_report_event( 1, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that a post was deleted.
 *
 * @param  integer $id The identifier of the post deleted.
 * @return void
 */
function sucuriscan_hook_delete_post( $id=0 ){
    sucuriscan_report_event( 3, 'core', 'Post deleted #'.$id );
}

/**
 * Send to Sucuri servers an alert advising that the state of a post was changed
 * from private to published. This will only applies for posts not pages.
 *
 * @param  integer $id The identifier of the post changed.
 * @return void
 */
function sucuriscan_hook_private_to_published( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );

    if( $data ){
        $title = $data->post_title;
        $p_type = ucwords($data->post_type);
    } else {
        $title = 'Unknown';
        $p_type = 'Publication';
    }

    // Check whether the post-type is being ignored to send notifications.
    if( !sucuriscan_is_ignored_event($p_type) ){
        $message = $p_type.' changed from private to published #'.$id.' ('.$title.')';
        sucuriscan_report_event( 2, 'core', $message );
        sucuriscan_notify_event( 'post_publication', $message );
    }
}

/**
 * Send to Sucuri servers an alert advising that a post was published.
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish( $id=0 ){
    $data = ( is_int($id) ? get_post($id) : FALSE );

    if( $data ){
        $title = $data->post_title;
        $p_type = ucwords($data->post_type);
        $action = ( $data->post_date == $data->post_modified ? 'created' : 'updated' );
    } else {
        $title = 'Unknown';
        $p_type = 'Publication';
        $action = 'published';
    }

    $message = $p_type.' was '.$action.' #'.$id.' ('.$title.')';
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_page( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_post( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_publish_phone( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Alias function for hook_publish()
 *
 * @param  integer $id The identifier of the post or page published.
 * @return void
 */
function sucuriscan_hook_xmlrpc_publish_post( $id=0 ){ sucuriscan_hook_publish($id); }

/**
 * Send to Sucuri servers an alert advising that a new link was added to the bookmarks.
 *
 * @param  integer $id Identifier of the new link created;
 * @return void
 */
function sucuriscan_hook_add_link( $id=0 ){
    $data = ( is_int($id) ? get_bookmark($id) : FALSE );

    if( $data ){
        $title = $data->link_name;
        $url = $data->link_url;
    } else {
        $title = 'Unknown';
        $url = 'undefined/url';
    }

    $message = 'New link added #'.$id.' ('.$title.': '.$url.')';
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'post_publication', $message );
}

/**
 * Send to Sucuri servers an alert advising that the theme of the site was changed.
 *
 * @param  string $title The name of the new theme selected to used through out the site.
 * @return void
 */
function sucuriscan_hook_switch_theme( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'Theme switched to: '.$title;
    sucuriscan_report_event( 3, 'core', $message );
    sucuriscan_notify_event( 'theme_switched', $message );
}

/**
 * Send to Sucuri servers an alert advising that a user account was deleted.
 *
 * @param  integer $id The identifier of the user account deleted.
 * @return void
 */
function sucuriscan_hook_delete_user( $id=0 ){
    sucuriscan_report_event( 3, 'core', 'User account deleted #'.$id );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to retrieve the password
 * of an user account was tried.
 *
 * @param  string $title The name of the user account involved in the trasaction.
 * @return void
 */
function sucuriscan_hook_retrieve_password( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    sucuriscan_report_event( 3, 'core', 'Password retrieval attempt for user: '.$title );
}

/**
 * Send to Sucuri servers an alert advising that a new user account was created.
 *
 * @param  integer $id The identifier of the new user account created.
 * @return void
 */
function sucuriscan_hook_user_register( $id=0 ){
    $data = ( is_int($id) ? get_userdata($id) : FALSE );
    $title = ( $data ? $data->display_name : 'Unknown' );

    $message = 'New user account registered #'.$id.' ('.$title.')';
    sucuriscan_report_event( 3, 'core', $message );
    sucuriscan_notify_event( 'user_registration', $message );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to login into the
 * administration panel was successful.
 *
 * @param  string $title The name of the user account involved in the transaction.
 * @return void
 */
function sucuriscan_hook_wp_login( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'User logged in: '.$title;
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'success_login', $message );
}

/**
 * Send to Sucuri servers an alert advising that an attempt to login into the
 * administration panel failed.
 *
 * @param  string $title The name of the user account involved in the transaction.
 * @return void
 */
function sucuriscan_hook_wp_login_failed( $title='' ){
    if( empty($title) ){ $title = 'Unknown'; }

    $message = 'User authentication failed: '.$title;
    sucuriscan_report_event( 2, 'core', $message );
    sucuriscan_notify_event( 'failed_login', $message );

    // Log the failed login in the internal datastore for future reports.
    $logged = sucuriscan_log_failed_login($title);

    // Check if the quantity of failed logins will be considered as a brute-force attack.
    if( $logged ){
        $failed_logins = sucuriscan_get_failed_logins();

        if( $failed_logins ){
            $max_time = 3600;
            $maximum_failed_logins = sucuriscan_get_option('sucuriscan_maximum_failed_logins');

            /**
             * If the time passed is within the hour, and the quantity of failed logins
             * registered in the datastore file is bigger than the maximum quantity of
             * failed logins allowed per hour (value configured by the administrator in the
             * settings page), then send an email notification reporting the event and
             * specifying that it may be a brute-force attack against the login page.
             */
            if(
                $failed_logins['diff_time'] <= $max_time
                && $failed_logins['count'] >= $maximum_failed_logins
            ){
                sucuriscan_report_failed_logins($failed_logins);
            }

            /**
             * If there time passed is superior to the hour, then reset the content of the
             * datastore file containing the failed logins so far, any entry in that file
             * will not be considered as part of a brute-force attack (if it exists) because
             * the time passed between the first and last login attempt is big enough to
             * mitigate the attack. We will consider the current failed login event as the
             * first entry of that file in case of future attempts during the next sixty
             * minutes.
             */
            elseif( $failed_logins['diff_time'] > $max_time ){
                sucuriscan_reset_failed_logins();
                sucuriscan_log_failed_login($title);
            }
        }
    }
}

/**
 * Send to Sucuri servers an alert advising that an attempt to reset the password
 * of an user account was executed.
 *
 * @return void
 */
function sucuriscan_hook_login_form_resetpass(){
    // Detecting WordPress 2.8.3 vulnerability - $key is array.
    if( isset($_GET['key']) && is_array($_GET['key']) ){
        sucuriscan_report_event( 3, 'core', 'Attempt to reset password by attacking WP/2.8.3 bug' );
    }
}

// Configure the hooks defined above to be triggered automatically.
if( isset($sucuriscan_hooks) ){
    foreach( $sucuriscan_hooks as $hook_name ){
        $hook_func = 'sucuriscan_hook_' . $hook_name;

        if( function_exists($hook_func) ){
            add_action( $hook_name, $hook_func, 50 );
        }
    }
}

if( !function_exists('sucuriscan_hook_undefined_actions') ){

    /**
     * Send a notifications to the administrator of some specific events that are
     * not triggered through an hooked action, but through a simple request in the
     * admin interface.
     *
     * @return integer Either one or zero representing the success or fail of the operation.
     */
    function sucuriscan_hook_undefined_actions(){

        // Plugin activation and/or deactivation.
        if(
            current_user_can('activate_plugins')
            && (
                ( isset($_GET['action']) && preg_match('/^(activate|deactivate)$/', $_GET['action']) ) ||
                ( isset($_POST['action']) && preg_match('/^(activate|deactivate)-selected$/', $_POST['action']))
            )
        ){
            $plugin_list = array();

            if(
                isset($_GET['plugin'])
                && !empty($_GET['plugin'])
                && strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== FALSE
            ){
                $action_d = $_GET['action'] . 'd';
                $plugin_list[] = $_GET['plugin'];
            }

            elseif( isset($_POST['checked']) ){
                $action_d = str_replace('-selected', 'd', $_POST['action']);
                $plugin_list = $_POST['checked'];
            }

            foreach( $plugin_list as $plugin ){
                $plugin_info = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
                $message = sprintf(
                    'Plugin %s: %s (v%s; %s)',
                    $action_d,
                    $plugin_info['Name'],
                    $plugin_info['Version'],
                    esc_attr($plugin)
                );

                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'plugin_' . $action_d, $message );
            }
        }

        // Plugin update request.
        elseif(
            current_user_can('update_plugins')
            && (
                ( isset($_GET['action']) && preg_match('/(upgrade-plugin|do-plugin-upgrade)/', $_GET['action']) ) ||
                ( isset($_POST['action']) && $_POST['action'] == 'update-selected' )
            )
        ){
            $plugin_list = array();

            if(
                isset($_GET['plugin'])
                && !empty($_GET['plugin'])
                && strpos($_SERVER['REQUEST_URI'], 'wp-admin/update.php') !== FALSE
            ){
                $plugin_list[] = $_GET['plugin'];
            }

            elseif( isset($_POST['checked']) ){
                $plugin_list = $_POST['checked'];
            }

            foreach( $plugin_list as $plugin ){
                $plugin_info = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
                $message = sprintf(
                    'Plugin request to be updated: %s (v%s; %s)',
                    $plugin_info['Name'],
                    $plugin_info['Version'],
                    esc_attr($plugin)
                );

                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'plugin_updated', $message );
            }
        }

        // Plugin installation request.
        elseif(
            current_user_can('install_plugins')
            && isset($_GET['action'])
            && preg_match('/^(install|upload)-plugin$/', $_GET['action'])
            && current_user_can('install_plugins')
        ){
            if( isset($_FILES['pluginzip']) ){
                $plugin = $_FILES['pluginzip']['name'];
            } elseif( isset($_GET['plugin']) ){
                $plugin = $_GET['plugin'];
            } else {
                $plugin = 'Unknown';
            }

            $message = 'Plugin request to be installed: ' . esc_attr($plugin);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'plugin_installed', $message );
        }

        // Plugin deletion request.
        elseif(
            current_user_can('delete_plugins')
            && isset($_POST['action'])
            && $_POST['action'] == 'delete-selected'
            && isset($_POST['verify-delete'])
            && $_POST['verify-delete'] == 1
        ){
            $plugin_list = (array) $_POST['checked'];

            foreach( $plugin_list as $plugin ){
                $plugin_info = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
                $message = sprintf(
                    'Plugin request to be deleted: %s (v%s; %s)',
                    $plugin_info['Name'],
                    $plugin_info['Version'],
                    esc_attr($plugin)
                );

                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'plugin_deleted', $message );
            }
        }

        // Plugin editor request.
        elseif(
            current_user_can('edit_plugins')
            && isset($_POST['action'])
            && $_POST['action'] == 'update'
            && isset($_POST['file'])
            && isset($_POST['plugin'])
            && strpos($_SERVER['REQUEST_URI'], 'plugin-editor.php') !== FALSE
        ){
            $message = 'Plugin editor modification: ' . esc_attr($_POST['file']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'theme_editor', $message );
        }

        // Theme editor request.
        elseif(
            current_user_can('edit_themes')
            && isset($_POST['action'])
            && $_POST['action'] == 'update'
            && isset($_POST['file'])
            && isset($_POST['theme'])
            && strpos($_SERVER['REQUEST_URI'], 'theme-editor.php') !== FALSE
        ){
            $message = 'Theme editor modification: ' . esc_attr($_POST['theme']) . '/' . esc_attr($_POST['file']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'theme_editor', $message );
        }

        // Theme activation and/or deactivation (same hook for switch_theme).
        // Theme installation request (hook not available).
        // Theme deletion request (hook not available).

        // Theme update request.
        elseif(
            current_user_can('update_themes')
            && isset($_GET['action'])
            && preg_match('/^(upgrade-theme|do-theme-upgrade)$/', $_GET['action'])
            && isset($_POST['checked'])
        ){
            $theme_list = (array) $_POST['checked'];

            foreach( $theme_list as $theme ){
                $theme_info = wp_get_theme($theme);
                $theme_name = ucwords($theme);
                $theme_version = '0.0';

                if( $theme_info->exists() ){
                    $theme_name = $theme_info->get('Name');
                    $theme_version = $theme_info->get('Version');
                }

                $message = sprintf(
                    'Theme request to be updated: %s (v%s; %s)',
                    $theme_name,
                    $theme_version,
                    esc_attr($theme)
                );

                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'theme_updated', $message );
            }
        }

        // WordPress update request.
        elseif(
            current_user_can('update_core')
            && isset($_GET['action'])
            && $_GET['action'] == 'do-core-reinstall'
            && isset($_POST['upgrade'])
            && isset($_POST['version'])
        ){
            $message = 'WordPress updated (or re-installed) to version: ' . esc_attr($_POST['version']);
            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'website_updated', $message );
        }

        // Widget addition or deletion.
        elseif(
            current_user_can('edit_theme_options')
            && isset($_POST['action'])
            && $_POST['action'] == 'save-widget'
            && isset($_POST['id_base'])
            && isset($_POST['sidebar'])
        ){
            if(
                isset($_POST['delete_widget'])
                && $_POST['delete_widget'] == 1
            ){
                $action_d = 'deleted';
                $action_text = 'deleted from';
            } else {
                $action_d = 'added';
                $action_text = 'added to';
            }

            $message = sprintf(
                'Widget %s (%s) %s %s (#%d; size %dx%d)',
                esc_attr($_POST['id_base']),
                esc_attr($_POST['widget-id']),
                $action_text,
                esc_attr($_POST['sidebar']),
                esc_attr($_POST['widget_number']),
                esc_attr($_POST['widget-width']),
                esc_attr($_POST['widget-height'])
            );

            sucuriscan_report_event( 3, 'core', $message );
            sucuriscan_notify_event( 'widget_' . $action_d, $message );
        }

        // Detect any Wordpress settings modification.
        elseif(
            isset($_POST['option_page'])
            && current_user_can('manage_options')
            && SucuriScan::sucuriscan_check_options_wpnonce()
        ){
            // Get the settings available in the database and compare them with the submission.
            $all_options = sucuriscan_get_wp_options();
            $options_changed = sucuriscan_what_options_were_changed($_POST);
            $options_changed_str = '';
            $options_changed_count = 0;

            // Generate the list of options changed.
            foreach( $options_changed['original'] as $option_name => $option_value ){
                $options_changed_count += 1;
                $options_changed_str .= sprintf(
                    "The value of the option <b>%s</b> was changed from <b>'%s'</b> to <b>'%s'</b>.<br>\n",
                    $option_name, $option_value, $options_changed['changed'][$option_name]
                );
            }

            // Get the option group (name of the page where the request was originated).
            $option_page = isset($_POST['option_page']) ? $_POST['option_page'] : 'options';
            $page_referer = FALSE;

            // Check which of these option groups where modified.
            switch( $option_page ){
                case 'options':
                    $page_referer = 'Global';
                    break;
                case 'general':    /* no_break */
                case 'writing':    /* no_break */
                case 'reading':    /* no_break */
                case 'discussion': /* no_break */
                case 'media':      /* no_break */
                case 'permalink':
                    $page_referer = ucwords($option_page);
                    break;
                default:
                    $page_referer = 'Common';
                    break;
            }

            if( $page_referer && $options_changed_count > 0 ){
                $message = $page_referer.' settings changed';
                sucuriscan_report_event( 3, 'core', $message );
                sucuriscan_notify_event( 'settings_updated', $message . "<br>\n" . $options_changed_str );
            }
        }

    }

    add_action( 'admin_init', 'sucuriscan_hook_undefined_actions' );
    add_action( 'login_form', 'sucuriscan_hook_undefined_actions' );
}

/**
 * CloudProxy monitoring page.
 *
 * It checks whether the WordPress core files are the original ones, and the state
 * of the themes and plugins reporting the availability of updates. It also checks
 * the user accounts under the administrator group.
 *
 * @return void
 */
function sucuriscan_monitoring_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Firewall (WAF)') );
    }

    // Process all form submissions.
    sucuriscan_monitoring_form_submissions();

    // Get the dynamic values for the template variables.
    $api_key = sucuriscan_cloudproxy_apikey();

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PageTitle' => 'Firewall WAF',
        'Monitoring.InstructionsVisibility' => 'visible',
        'Monitoring.Settings' => sucuriscan_monitoring_settings($api_key),
        'Monitoring.Logs' => sucuriscan_monitoring_logs($api_key),

        /* Pseudo-variables for the monitoring logs. */
        'AuditLogs.List' => '',
        'AuditLogs.CountText' => '',
        'AuditLogs.DenialTypeOptions' => '',
        'AuditLogs.NoItemsVisibility' => '',
        'AuditLogs.PaginationVisibility' => '',
        'AuditLogs.AuditPagination' => '',
    );

    if( $api_key ){
        $template_variables['Monitoring.InstructionsVisibility'] = 'hidden';
    }

    echo sucuriscan_get_template('monitoring', $template_variables);
}

/**
 * Process the requests sent by the form submissions originated in the monitoring
 * page, all forms must have a nonce field that will be checked agains the one
 * generated in the template render function.
 *
 * @return void
 */
function sucuriscan_monitoring_form_submissions(){

    if( sucuriscan_check_page_nonce() ){

        // Add and/or Update the Sucuri WAF API Key (do it before anything else).
        $option_name = 'sucuriscan_cloudproxy_apikey';

        if( isset($_POST[$option_name]) ){
            $api_key = $_POST[$option_name];

            if( sucuriscan_valid_cloudproxy_apikey($api_key) ){
                update_option($option_name, $api_key);
                sucuriscan_info( 'Sucuri CloudProxy WAF API key saved successfully' );
            } elseif( empty($api_key) ){
                delete_option($option_name);
                sucuriscan_info( 'Sucuri CloudProxy WAF API key removed successfully' );
            } else {
                sucuriscan_error( 'Invalid CloudProxy API key, check your settings and try again.' );
            }
        }

        // Flush the cache of the site(s) associated with the API key.
        if( isset($_POST['sucuriscan_clear_cache']) ){
            $clear_cache_resp = sucuriscan_cloudproxy_clear_cache();

            if( $clear_cache_resp ){
                if( isset($clear_cache_resp->messages[0]) ){
                    sucuriscan_info($clear_cache_resp->messages[0]);
                } else {
                    sucuriscan_error('Could not clear the cache of your site, try later again.');
                }
            } else {
                sucuriscan_error( 'CloudProxy WAF is not enabled on your site, or your API key is invalid.' );
            }
        }

    }

}

/**
 * Generate the HTML code for the monitoring settings panel.
 *
 * @param  string $api_key The CloudProxy API key.
 * @return string          The parsed-content of the monitoring settings panel.
 */
function sucuriscan_monitoring_settings( $api_key='' ){
    $template_variables = array(
        'Monitoring.APIKey' => '',
        'Monitoring.SettingsVisibility' => 'hidden',
        'Monitoring.SettingOptions' => '',
    );

    if( $api_key ){
        $settings = sucuriscan_cloudproxy_settings($api_key);

        $template_variables['Monitoring.APIKey'] = $api_key['string'];

        if( $settings ){
            $counter = 0;
            $template_variables['Monitoring.SettingsVisibility'] = 'visible';
            $settings = sucuriscan_explain_monitoring_settings($settings);

            foreach( $settings as $option_name => $option_value ){
                // Change the name of some options.
                if( $option_name == 'internal_ip' ){
                    $option_name = 'hosting_ip';
                }

                $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';
                $option_title = ucwords(str_replace('_', chr(32), $option_name));

                // Generate a HTML list when the option's value is an array.
                if( is_array($option_value) ){
                    $css_scrollable = count($option_value) > 10 ? 'sucuriscan-list-as-table-scrollable' : '';
                    $html_list  = '<ul class="sucuriscan-list-as-table ' . $css_scrollable . '">';

                    foreach( $option_value as $single_value ){
                        $html_list .= '<li>' . $single_value . '</li>';
                    }

                    $html_list .= '</ul>';
                    $option_value = $html_list;
                }

                // Parse the snippet template and replace the pseudo-variables.
                $template_variables['Monitoring.SettingOptions'] .= sucuriscan_get_snippet('monitoring-settings', array(
                    'Monitoring.OptionCssClass' => $css_class,
                    'Monitoring.OptionName' => $option_title,
                    'Monitoring.OptionValue' => $option_value,
                ));
                $counter += 1;
            }
        }
    }

    return sucuriscan_get_section( 'monitoring-settings', $template_variables );
}

/**
 * Converts the value of some of the monitoring settings into a human-readable
 * text, for example changing numbers or variable names into a more explicit
 * text so the administrator can understand the meaning of these settings.
 *
 * @param  array $settings A hash with the settings of a CloudProxy account.
 * @return array           The explained version of the CloudProxy settings.
 */
function sucuriscan_explain_monitoring_settings( $settings=array() ){
    if( $settings ){
        foreach( $settings as $option_name => $option_value ){
            switch( $option_name ){
                case 'security_level':
                    $new_value = ucwords($option_value);
                    break;
                case 'proxy_active':
                    $new_value = ( $option_value == 1 ) ? 'Active' : 'not active';
                    break;
                case 'cache_mode':
                    $new_value = sucuriscan_cache_mode_title($option_value);
                    break;
            }

            if( isset($new_value) ){
                $settings->{$option_name} = $new_value;
            }
        }

        return $settings;
    }

    return FALSE;
}

/**
 * Get an explaination of the meaning of the value set for the account's attribute cache_mode.
 *
 * @param  string $mode The value set for the cache settings of the site.
 * @return string       Explaination of the meaning of the cache_mode value.
 */
function sucuriscan_cache_mode_title( $mode='' ){
    $title = '';

    switch( $mode ){
        case 'docache':      $title = 'Enabled (recommended)'; break;
        case 'sitecache':    $title = 'Site caching (using your site headers)'; break;
        case 'nocache':      $title = 'Minimial (only for a few minutes)'; break;
        case 'nocacheatall': $title = 'Caching didabled (use with caution)'; break;
        default:             $title = 'Unknown'; break;
    }

    return $title;
}

/**
 * Generate the HTML code for the monitoring logs panel.
 *
 * @param  string $api_key The CloudProxy API key.
 * @return string          The parsed-content of the monitoring logs panel.
 */
function sucuriscan_monitoring_logs( $api_key='' ){
    $template_variables = array(
        'AuditLogs.List' => '',
        'AuditLogs.CountText' => 0,
        'AuditLogs.DenialTypeOptions' => '',
        'AuditLogs.NoItemsVisibility' => 'visible',
        'AuditLogs.PaginationVisibility' => 'hidden',
        'AuditLogs.AuditPagination' => '',
        'AuditLogs.TargetDate' => '',
        'AuditLogs.DateYears' => sucuriscan_monitoring_dates('years'),
        'AuditLogs.DateMonths' => sucuriscan_monitoring_dates('months'),
        'AuditLogs.DateDays' => sucuriscan_monitoring_dates('days'),
    );

    $date = date('Y-m-d');

    if( $api_key ){
        // Retrieve the date filter from the request (if any).
        if( isset($_GET['date']) ){
            $date = $_GET['date'];
        }

        elseif(
            isset($_POST['sucuriscan_year']) &&
            isset($_POST['sucuriscan_month']) &&
            isset($_POST['sucuriscan_day'])
        ){
            $date = sprintf(
                '%s-%s-%s',
                $_POST['sucuriscan_year'],
                $_POST['sucuriscan_month'],
                $_POST['sucuriscan_day']
            );
        }

        $logs_data = sucuriscan_cloudproxy_logs( $api_key, $date );

        if( $logs_data ){
            add_thickbox(); /* Include the Thickbox library. */
            $template_variables['AuditLogs.NoItemsVisibility'] = 'hidden';
            $template_variables['AuditLogs.CountText'] = $logs_data->limit . '/' . $logs_data->total_lines;
            $template_variables['AuditLogs.List'] = sucuriscan_monitoring_access_logs($logs_data->access_logs);
            $template_variables['AuditLogs.DenialTypeOptions'] = sucuriscan_monitoring_denial_types($logs_data->access_logs);
        }
    }

    $template_variables['AuditLogs.TargetDate'] = htmlentities($date);

    return sucuriscan_get_section( 'monitoring-logs', $template_variables );
}

/**
 * Generate the HTML code to show the table with the access-logs.
 *
 * @param  array  $access_logs The logs retrieved from the remote API service.
 * @return string              The HTML code to show the access-logs in the page as a table.
 */
function sucuriscan_monitoring_access_logs( $access_logs=array() ){
    $logs_html = '';

    if( $access_logs && !empty($access_logs) ){
        $counter = 0;
        $needed_attrs = array(
            'request_date',
            'request_time',
            'request_timezone',
            'remote_addr',
            'sucuri_block_reason',
            'resource_path',
            'request_method',
            'http_protocol',
            'http_status',
            'http_status_title',
            'http_bytes_sent',
            'http_referer',
            'http_user_agent',
        );

        $filter_by_denial_type = FALSE;
        $filter_by_keyword = FALSE;
        $filter_query = FALSE;

        if( isset($_POST['sucuriscan_monitoring_denial_type']) ){
            $filter_by_denial_type = TRUE;
            $filter_query = htmlentities($_POST['sucuriscan_monitoring_denial_type']);
        }

        if( isset($_POST['sucuriscan_monitoring_log_filter']) ){
            $filter_by_keyword = TRUE;
            $filter_query = htmlentities($_POST['sucuriscan_monitoring_log_filter']);
        }

        foreach( $access_logs as $access_log ){
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
            $audit_log_snippet = array(
                'AuditLog.Id' => $counter,
                'AuditLog.CssClass' => $css_class,
            );

            // If there is a filter, check the access_log data and break the operation if needed.
            if( $filter_query ){
                if( $filter_by_denial_type ){
                    $denial_type_slug = sucuriscan_str_human2var($access_log->sucuri_block_reason);

                    if( $denial_type_slug != $filter_query ){ continue; }
                }

                if(
                    $filter_by_keyword
                    && strpos($access_log->remote_addr, $filter_query) === FALSE
                    && strpos($access_log->resource_path, $filter_query) === FALSE
                ){
                    continue;
                }
            }

            // Generate (dynamically) the pseudo-variables for the template.
            foreach( $needed_attrs as $attr_name ){
                $attr_value = '';

                $attr_title = str_replace('_', chr(32), $attr_name);
                $attr_title = ucwords($attr_title);
                $attr_title = str_replace(chr(32), '', $attr_title);
                $attr_title = 'AuditLog.' . $attr_title;

                if( isset($access_log->{$attr_name}) ){
                    $attr_value = $access_log->{$attr_name};
                }

                $audit_log_snippet[$attr_title] = $attr_value;
            }

            $logs_html .= sucuriscan_get_snippet('monitoring-logs', $audit_log_snippet);
            $counter += 1;
        }
    }

    return $logs_html;
}

/**
 * Get a list of denial types using the reason of the blocking of a request from
 * the from the audit logs. Examples of denial types can be: "Bad bot access
 * denied", "Access to restricted folder", "Blocked by IDS", etc.
 *
 * @param  array   $access_logs A list of objects with the detailed version of each request blocked by our service.
 * @param  boolean $in_html     Whether the list should be converted to a HTML select options or not.
 * @return array                Either a list of unique blocking types, or a HTML code.
 */
function sucuriscan_monitoring_denial_types( $access_logs=array(), $in_html=TRUE ){
    $types = array();
    $selected = '';

    if( $access_logs && !empty($access_logs) ){
        foreach( $access_logs as $access_log ){
            if( !array_key_exists($access_log->sucuri_block_reason, $types) ){
                $denial_type_k = sucuriscan_str_human2var($access_log->sucuri_block_reason);
                $types[$denial_type_k] = $access_log->sucuri_block_reason;
            }
        }
    }

    if( $in_html ){
        $html_types = '<option value="">Filter</option>';

        if( isset($_REQUEST['sucuriscan_monitoring_denial_type']) ){
            $selected = htmlentities($_REQUEST['sucuriscan_monitoring_denial_type']);
        }

        foreach( $types as $type_key => $type_value ){
            $selected_tag = ( $type_key == $selected ) ? 'selected="selected"' : '';
            $html_types .= sprintf( '<option value="%s" %s>%s</option>', $type_key, $selected_tag, $type_value );
        }

        return $html_types;
    }

    return $types;
}

/**
 * Get a list of years, months or days depending of the type specified.
 *
 * @param  string  $type    Either years, months or days.
 * @param  boolean $in_html Whether the list should be converted to a HTML select options or not.
 * @return array            Either an array with the expected values, or a HTML code.
 */
function sucuriscan_monitoring_dates( $type='', $in_html=TRUE ){
    $options = array();
    $selected = '';

    switch( $type ){
        case 'years':
            $current_year = (int) date('Y');
            $max_years = 5; /* Maximum number of years to keep the logs. */
            $options = range( ($current_year - $max_years), $current_year );

            if( isset($_REQUEST['sucuriscan_year']) ){
                $selected = $_REQUEST['sucuriscan_year'];
            }
            break;
        case 'months':
            $options = array(
                '01' => 'January',
                '02' => 'February',
                '03' => 'March',
                '04' => 'April',
                '05' => 'May',
                '06' => 'June',
                '07' => 'July',
                '08' => 'August',
                '09' => 'September',
                '10' => 'October',
                '11' => 'November',
                '12' => 'December'
            );

            if( isset($_REQUEST['sucuriscan_month']) ){
                $selected = $_REQUEST['sucuriscan_month'];
            }
            break;
        case 'days':
            $options = range(1, 31);

            if( isset($_REQUEST['sucuriscan_day']) ){
                $selected = $_REQUEST['sucuriscan_day'];
            }
            break;
    }

    if( $in_html ){
        $html_options = '';

        foreach( $options as $key => $value ){
            if( is_numeric($value) ){ $value = str_pad($value, 2, 0, STR_PAD_LEFT); }

            if( $type != 'months' ){ $key = $value; }

            $selected_tag = ( $key == $selected ) ? 'selected="selected"' : '';
            $html_options .= sprintf( '<option value="%s" %s>%s</option>', $key, $selected_tag, $value );
        }

        return $html_options;
    }

    return $options;
}

/**
 * Sucuri one-click hardening page.
 *
 * It loads all the functions defined in /lib/hardening.php and shows the forms
 * that the administrator can use to harden multiple parts of the site.
 *
 * @return void
 */
function sucuriscan_hardening_page(){

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Hardening') );
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( !wp_verify_nonce($_POST['sucuriscan_hardening_nonce'], 'sucuriscan_hardening_nonce') ){
            unset($_POST['wpsucuri-doharden']);
        }
    }

    ob_start();
    ?>

    <div id="poststuff">
        <form method="post">
            <input type="hidden" name="sucuriscan_hardening_nonce" value="<?php echo wp_create_nonce('sucuriscan_hardening_nonce'); ?>" />
            <input type="hidden" name="wpsucuri-doharden" value="wpsucuri-doharden" />

            <?php
            sucuriscan_harden_version();
            sucuriscan_cloudproxy_enabled();
            sucuriscan_harden_removegenerator();
            sucuriscan_harden_upload();
            sucuriscan_harden_wpcontent();
            sucuriscan_harden_wpincludes();
            sucuriscan_harden_phpversion();
            sucuriscan_harden_secretkeys();
            sucuriscan_harden_readme();
            sucuriscan_harden_adminuser();
            sucuriscan_harden_fileeditor();
            sucuriscan_harden_dbtables();
            ?>
        </form>
    </div>

    <?php
    $_html = ob_get_contents();
    ob_end_clean();
    echo sucuriscan_get_base_template($_html, array(
        'PageTitle' => 'Hardening',
        'PageContent' => $_html,
        'PageStyleClass' => 'hardening'
    ));
    return;
}

/**
 * Generate the HTML code necessary to show a form with the options to harden
 * a specific part of the WordPress installation, if the Status variable is
 * set as a positive integer the button is shown as "unharden".
 *
 * @param  string  $title       Title of the panel.
 * @param  integer $status      Either one or zero representing the state of the hardening, one for secure, zero for insecure.
 * @param  string  $type        Name of the hardening option, this will be used through out the form generation.
 * @param  string  $messageok   Message that will be shown if the hardening was executed.
 * @param  string  $messagewarn Message that will be shown if the hardening is not executed.
 * @param  string  $desc        Optional description of the hardening.
 * @param  string  $updatemsg   Optional explanation of the hardening after the submission of the form.
 * @return void
 */
function sucuriscan_harden_status( $title='', $status=0, $type='', $messageok='', $messagewarn='', $desc=NULL, $updatemsg=NULL ){ ?>
    <div class="postbox">
        <h3><?php _e($title) ?></h3>

        <div class="inside">
            <?php if( $desc != NULL ): ?>
                <p><?php _e($desc) ?></p>
            <?php endif; ?>

            <div class="sucuriscan-hstatus sucuriscan-hstatus-<?php _e($status) ?>">
                <?php if( $type != NULL ): ?>
                    <?php if( $status == 1 ): ?>
                        <input type="submit" name="<?php _e($type) ?>_unharden" value="Revert hardening" class="button-secondary" />
                    <?php else: ?>
                        <input type="submit" name="<?php _e($type) ?>" value="Harden" class="button-primary" />
                    <?php endif; ?>
                <?php endif; ?>

                <span>
                    <?php if( $status == 1 ): ?>
                        <?php _e($messageok) ?>
                    <?php else: ?>
                        <?php _e($messagewarn) ?>
                    <?php endif; ?>
                </span>
            </div>

            <?php if( $updatemsg != NULL ): ?>
                <p><?php _e($updatemsg) ?></p>
            <?php endif; ?>
        </div>
    </div>

<?php }

/**
 * Check whether the version number of the WordPress installed is the latest
 * version available officially.
 *
 * @return void
 */
function sucuriscan_harden_version(){
    global $wp_version;

    $updates = get_core_updates();
    $cp = ( !is_array($updates) || empty($updates) ? 1 : 0 );

    if( isset($updates[0]) && $updates[0] instanceof stdClass ){
        if(
            $updates[0]->response == 'latest'
            || $updates[0]->response == 'development'
        ){
            $cp = 1;
        }
    }

    if( strcmp($wp_version, '3.7') < 0 ){
        $cp = 0;
    }

    $wp_version = htmlspecialchars($wp_version);
    $initial_msg = 'Why keep your site updated? WordPress is an open-source
        project which means that with every update the details of the changes made
        to the source code are made public, if there were security fixes then
        someone with malicious intent can use this information to attack any site
        that has not been upgraded.';
    $messageok = sprintf('Your WordPress installation (%s) is current.', $wp_version);
    $messagewarn = sprintf(
        'Your current version (%s) is not current.<br>
        <a href="update-core.php" class="button-primary">Update now!</a>',
        $wp_version
    );

    sucuriscan_harden_status( 'Verify WordPress version', $cp, NULL, $messageok, $messagewarn, $initial_msg );
}

/**
 * Notify the state of the hardening for the removal of the Generator tag in
 * HTML code printed by WordPress to show the current version number of the
 * installation.
 *
 * @return void
 */
function sucuriscan_harden_removegenerator(){
    sucuriscan_harden_status(
        'Remove WordPress version',
        1,
        NULL,
        'WordPress version properly hidden',
        NULL,
        'It checks if your WordPress version is being hidden from being displayed '
        .'in the generator tag (enabled by default with this plugin).'
    );
}

/**
 * Check whether the WordPress upload folder is protected or not.
 *
 * A htaccess file is placed in the upload folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself.
 *
 * @return void
 */
function sucuriscan_harden_upload(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = dirname(sucuriscan_dir_filepath())."/.htaccess";

    if( !is_readable($htaccess_upload) ){
        $cp = 0;
    } else {
        $cp = 0;
        $fcontent = file($htaccess_upload);

        foreach( $fcontent as $fline ){
            if( strpos($fline, 'deny from all') !== FALSE ){
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_upload']) && $cp == 0 ){
            if( @file_put_contents($htaccess_upload, "\n<Files *.php>\ndeny from all\n</Files>") === FALSE ){
                $upmsg = sucuriscan_error('ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.');
            } else {
                $upmsg = sucuriscan_info('COMPLETE: Upload directory successfully hardened');
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_upload_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;

                if( preg_match('/<Files \*\.php>\ndeny from all\n<\/Files>/', $htaccess_content, $match) ){
                    $htaccess_content = str_replace("<Files *.php>\ndeny from all\n</Files>", '', $htaccess_content);
                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }

                sucuriscan_info('Hardening removed for the WordPress upload directory <code>/wp-content/uploads</code>');
            } else {
                sucuriscan_error(
                    '<code>wp-content/uploads/.htaccess</code> does not exists or is not
                    writable, you will need to remove the following code (manually):
                    <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>'
                );
            }
        }
    }

    sucuriscan_harden_status(
        'Protect uploads directory',
        $cp,
        'sucuriscan_harden_upload',
        'Upload directory properly hardened',
        'Upload directory not hardened',
        'It checks if your upload directory allows PHP execution or if it is browsable.',
        $upmsg
    );
}

/**
 * Check whether the WordPress content folder is protected or not.
 *
 * A htaccess file is placed in the content folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself.
 *
 * @return void
 */
function sucuriscan_harden_wpcontent(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = ABSPATH . '/wp-content/.htaccess';

    if( !is_readable($htaccess_upload) ){
        $cp = 0;
    } else {
        $cp = 0;
        $fcontent = file($htaccess_upload);

        foreach( $fcontent as $fline ){
            if( strpos($fline, 'deny from all') !== FALSE ){
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_wpcontent']) && $cp == 0 ){
            if( @file_put_contents($htaccess_upload, "\n<Files *.php>\ndeny from all\n</Files>") === FALSE ){
                $upmsg = sucuriscan_error('ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.');
            } else {
                $upmsg = sucuriscan_info('COMPLETE: wp-content directory successfully hardened');
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_wpcontent_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;

                if( preg_match('/<Files \*\.php>\ndeny from all\n<\/Files>/', $htaccess_content, $match) ){
                    $htaccess_content = str_replace("<Files *.php>\ndeny from all\n</Files>", '', $htaccess_content);
                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }

                sucuriscan_info('WP-Content directory protection reverted.');
            } else {
                sucuriscan_info(
                    '<code>wp-content/.htaccess</code> does not exists or is not writable,
                    you will need to remove the following code manually there:
                    <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>'
                );
            }
        }
    }

    sucuriscan_harden_status(
        'Restrict wp-content access',
        $cp,
        'sucuriscan_harden_wpcontent',
        'WP-content directory properly hardened',
        'WP-content directory not hardened',
        'This option blocks direct PHP access to any file inside wp-content. If you experience any '
        .'issue after this with a theme or plugin in your site, like for example images not displaying, '
        .'remove the <code>.htaccess</code> file located at the <code>/wp-content/</code> directory.',
        $upmsg
    );
}

/**
 * Check whether the WordPress includes folder is protected or not.
 *
 * A htaccess file is placed in the includes folder denying the access to any php
 * file that could be uploaded through a vulnerability in a Plugin, Theme or
 * WordPress itself, there are some exceptions for some specific files that must
 * be available publicly.
 *
 * @return void
 */
function sucuriscan_harden_wpincludes(){
    $cp = 1;
    $upmsg = NULL;
    $htaccess_upload = ABSPATH . '/wp-includes/.htaccess';

    if( !is_readable($htaccess_upload) ){
        $cp = 0;
    } else {
        $cp = 0;
        $fcontent = file($htaccess_upload);

        foreach( $fcontent as $fline ){
            if( strpos($fline, 'deny from all') !== FALSE ){
                $cp = 1;
                break;
            }
        }
    }

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_wpincludes']) && $cp == 0 ){
            if( @file_put_contents($htaccess_upload, "\n<Files *.php>\ndeny from all\n</Files>\n<Files wp-tinymce.php>\nallow from all\n</Files>\n")===FALSE ){
                $upmsg = sucuriscan_error('ERROR: Unable to create <code>.htaccess</code> file, folder destination is not writable.');
            } else {
                $upmsg = sucuriscan_info('COMPLETE: wp-includes directory successfully hardened.');
                $cp = 1;
            }
        }

        elseif( isset($_POST['sucuriscan_harden_wpincludes_unharden']) ){
            $htaccess_upload_writable = ( file_exists($htaccess_upload) && is_writable($htaccess_upload) ) ? TRUE : FALSE;
            $htaccess_content = $htaccess_upload_writable ? file_get_contents($htaccess_upload) : '';

            if( $htaccess_upload_writable ){
                $cp = 0;
                if( preg_match_all('/<Files (\*|wp-tinymce|ms-files)\.php>\n(deny|allow) from all\n<\/Files>/', $htaccess_content, $match) ){
                    foreach($match[0] as $restriction){
                        $htaccess_content = str_replace($restriction, '', $htaccess_content);
                    }

                    @file_put_contents($htaccess_upload, $htaccess_content, LOCK_EX);
                }
                sucuriscan_info('WP-Includes directory protection reverted.');
            } else {
                sucuriscan_error(
                    '<code>wp-includes/.htaccess</code> does not exists or is not
                    writable, you will need to remove the following code manually
                    there: <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>'
                );
            }
        }
    }

    sucuriscan_harden_status(
        'Restrict wp-includes access',
        $cp,
        'sucuriscan_harden_wpincludes',
        'WP-Includes directory properly hardened',
        'WP-Includes directory not hardened',
        'This option blocks direct PHP access to any file inside <code>wp-includes</code>.',
        $upmsg
    );
}

/**
 * Check the version number of the PHP interpreter set to work with the site,
 * is considered that old versions of the PHP interpreter are insecure.
 *
 * @return void
 */
function sucuriscan_harden_phpversion(){
    $phpv = phpversion();
    $cp = ( strncmp($phpv, '5.', 2) < 0 ) ? 0 : 1;

    sucuriscan_harden_status(
        'Verify PHP version',
        $cp,
        NULL,
        'Using an updated version of PHP (' . $phpv . ')',
        'The version of PHP you are using (' . $phpv . ') is not current, not recommended, and/or not supported',
        'This checks if you have the latest version of PHP installed.',
        NULL
    );
}

/**
 * Check whether the site is behind a secure proxy server or not.
 *
 * @return void
 */
function sucuriscan_cloudproxy_enabled(){
    $btn_string = '';
    $enabled = sucuriscan_is_behind_cloudproxy();
    $status = 1;

    if( $enabled !== TRUE ){
        $status = 0;
        $btn_string = '<a href="http://cloudproxy.sucuri.net/" target="_blank" class="button button-primary">Harden</a>';
    }

    sucuriscan_harden_status(
        'Website Firewall protection',
        $status,
        NULL,
        'Your website is protected by a Website Firewall (WAF)',
        $btn_string . 'Your website is not protected by a Website Firewall (WAF)',
        'A WAF is a protection layer for your web site, blocking all sort of attacks (brute force attempts, DDoS, '
        .'SQL injections, etc) and helping it remain malware and blacklist free. This test checks if your site is '
        .'using <a href="http://cloudproxy.sucuri.net/" target="_blank">Sucuri\'s CloudProxy WAF</a> to protect your site. ',
        NULL
    );
}

/**
 * Check whether the Wordpress configuration file has the security keys recommended
 * to avoid any unauthorized access to the interface.
 *
 * WordPress Security Keys is a set of random variables that improve encryption of
 * information stored in the user’s cookies. There are a total of four security
 * keys: AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, and NONCE_KEY.
 *
 * @return void
 */
function sucuriscan_harden_secretkeys(){
    $wp_config_path = sucuriscan_get_wpconfig_path();

    if( $wp_config_path ){
        $cp = 1;
        $message = 'The main configuration file was found at: <code>'.$wp_config_path.'</code><br>';

        $secret_key_names = array(
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
            'AUTH_SALT',
            'SECURE_AUTH_SALT',
            'LOGGED_IN_SALT',
            'NONCE_SALT',
        );

        foreach( $secret_key_names as $key_name){
            if( !defined($key_name) ){
                $cp = 0;
                $message .= 'The secret key <strong>'.$key_name.'</strong> is not defined.<br>';
            } elseif( constant($key_name) == 'put your unique phrase here' ){
                $cp = 0;
                $message .= 'The secret key <strong>'.$key_name.'</strong> is not properly set.<br>';
            }
        }

        if( $cp == 0 ){
            $admin_url = admin_url('admin.php?page=sucuriscan_posthack');
            $message .= '<br><a href="'.$admin_url.'" class="button button-primary">Update WP-Config Keys</a><br>';
        }
    }else{
        $cp = 0;
        $message = 'The <code>wp-config</code> file was not found.<br>';
    }

    $message .= '<br>It checks whether you have proper random keys/salts created for WordPress. A
        <a href="http://codex.wordpress.org/Editing_wp-config.php#Security_Keys" target="_blank">
        secret key</a> makes your site harder to hack and access harder to crack by adding
        random elements to the password. In simple terms, a secret key is a password with
        elements that make it harder to generate enough options to break through your
        security barriers.';

    sucuriscan_harden_status(
        'Secret keys validity',
        $cp,
        NULL,
        'WordPress secret keys and salts properly created',
        'WordPress secret keys and salts not set, we recommend creating them for security reasons',
        $message,
        NULL
    );
}

/**
 * Check whether the "readme.html" file is still available in the root of the
 * site or not, which can lead to an attacker to know which version number of
 * Wordpress is being used and search for possible vulnerabilities.
 *
 * @return void
 */
function sucuriscan_harden_readme(){
    $upmsg = NULL;
    $cp = is_readable(ABSPATH.'/readme.html') ? 0 : 1;

    if( isset($_POST['wpsucuri-doharden']) ){
        if( isset($_POST['sucuriscan_harden_readme']) && $cp == 0 ){
            if( @unlink(ABSPATH.'/readme.html') === FALSE ){
                $upmsg = sucuriscan_error('Unable to remove <code>readme.html</code> file.');
            } else {
                $cp = 1;
                $upmsg = sucuriscan_info('<code>readme.html</code> file removed successfully.');
            }
        }

        elseif( isset($_POST['sucuriscan_harden_readme_unharden']) ){
            sucuriscan_error('We can not revert this action, you should create the <code>readme.html</code> file at your own.');
        }
    }

    sucuriscan_harden_status(
        'Information leakage (readme.html)',
        $cp,
        ( $cp == 0 ? 'sucuriscan_harden_readme' : NULL ),
        '<code>readme.html</code> file properly deleted',
        '<code>readme.html</code> not deleted and leaking the WordPress version',
        'It checks whether you have the <code>readme.html</code> file available that leaks your WordPress version',
        $upmsg
    );
}

/**
 * Check whether the main administrator user still has the default name "admin"
 * or not, which can lead to an attacker to perform a brute force attack.
 *
 * @return void
 */
function sucuriscan_harden_adminuser(){
    global $wpdb;

    $upmsg = NULL;
    $res = $wpdb->get_results("SELECT user_login FROM {$wpdb->prefix}users WHERE user_login = 'admin'");
    $account_removed = ( count($res) == 0 ? 1 : 0 );

    if( $account_removed == 0 ){
        $upmsg = '<i><strong>We do not offer the option</strong> to automatically change the user name.
        Go to the <a href="'.admin_url('users.php').'" target="_blank">user list</a> and create a new
        admin user name. Once created, log in as that user and remove the default "admin" from there
        (make sure to assign all the admin posts to the new user too!).</i>';
    }

    sucuriscan_harden_status(
        'Default admin account',
        $account_removed,
        NULL,
        'Default admin user account (admin) not being used',
        'Default admin user account (admin) being used. Not recommended',
        'It checks whether you have the default <code>admin</code> account enabled, security guidelines recommend creating a new admin user name.',
        $upmsg
    );
}

/**
 * Enable or disable the user of the built-in Wordpress file editor.
 *
 * @return void
 */
function sucuriscan_harden_fileeditor(){
    $file_editor_disabled = defined('DISALLOW_FILE_EDIT') ? DISALLOW_FILE_EDIT : FALSE;

    if( isset($_POST['wpsucuri-doharden']) ){
        $current_time = date('r');
        $wp_config_path = sucuriscan_get_wpconfig_path();

        $wp_config_writable = ( file_exists($wp_config_path) && is_writable($wp_config_path) ) ? TRUE : FALSE;
        $new_wpconfig = $wp_config_writable ? file_get_contents($wp_config_path) : '';

        if( isset($_POST['sucuriscan_harden_fileeditor']) ){
            if( $wp_config_writable ){
                if( preg_match('/(.*define\(.DB_COLLATE..*)/', $new_wpconfig, $match) ){
                    $disallow_fileedit_definition = "\n\ndefine('DISALLOW_FILE_EDIT', TRUE); // Sucuri Security: {$current_time}\n";
                    $new_wpconfig = str_replace($match[0], $match[0].$disallow_fileedit_definition, $new_wpconfig);
                }

                @file_put_contents($wp_config_path, $new_wpconfig, LOCK_EX);
                sucuriscan_info( 'WP-Config file updated successfully, the plugin and theme editor were disabled.' );
                $file_editor_disabled = TRUE;
            } else {
                sucuriscan_error( 'The <code>wp-config.php</code> file is not in the default location
                    or is not writable, you will need to put the following code manually there:
                    <code>define("DISALLOW_FILE_EDIT", TRUE);</code>' );
            }
        }

        elseif( isset($_POST['sucuriscan_harden_fileeditor_unharden']) ){
            if( preg_match("/(.*define\('DISALLOW_FILE_EDIT', TRUE\);.*)/", $new_wpconfig, $match) ){
                if( $wp_config_writable ){
                    $new_wpconfig = str_replace("\n{$match[1]}", '', $new_wpconfig);
                    file_put_contents($wp_config_path, $new_wpconfig, LOCK_EX);
                    sucuriscan_info( 'WP-Config file updated successfully, the plugin and theme editor were enabled.' );
                    $file_editor_disabled = FALSE;
                } else {
                    sucuriscan_error( 'The <code>wp-config.php</code> file is not in the default location
                        or is not writable, you will need to remove the following code manually from there:
                        <code>define("DISALLOW_FILE_EDIT", TRUE);</code>' );
                }
            } else {
                sucuriscan_error( 'We did not find a definition to disallow the file editor.' );
            }
        }
    }

    $message = 'Occasionally you may wish to disable the plugin or theme editor to prevent overzealous users
        from being able to edit sensitive files and potentially crash the site. Disabling these also
        provides an additional layer of security if a hacker gains access to a well-privileged user
        account.';

    sucuriscan_harden_status(
        'Plugin &amp; Theme editor',
        ( $file_editor_disabled === FALSE ? 0 : 1 ),
        'sucuriscan_harden_fileeditor',
        'File editor for Plugins and Themes is disabled',
        'File editor for Plugins and Themes is enabled',
        $message,
        NULL
    );
}

/**
 * Check whether the prefix of each table in the database designated for the site
 * is the same as the default prefix defined by Wordpress "_wp", in that case the
 * "harden" button will generate randomly a new prefix and rename all those tables.
 *
 * @return void
 */
function sucuriscan_harden_dbtables(){
    global $table_prefix;

    $hardened = ( $table_prefix == 'wp_' ? 0 : 1 );

    sucuriscan_harden_status(
        'Database table prefix',
        $hardened,
        NULL,
        'Database table prefix properly modified',
        'Database table set to the default value <code>wp_</code>.',
        'It checks whether your database table prefix has been changed from the default <code>wp_</code>',
        '<strong>Be aware that this hardening procedure can cause your site to go down</strong>'
    );
}

/**
 * WordPress core integrity page.
 *
 * It checks whether the WordPress core files are the original ones, and the state
 * of the themes and plugins reporting the availability of updates. It also checks
 * the user accounts under the administrator group.
 *
 * @return void
 */
function sucuriscan_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Integrity Check') );
    }

    sucuriscan_integrity_form_submissions();

    $template_variables = array(
        'WordpressVersion' => sucuriscan_wordpress_outdated(),
        'AuditLogs' => sucuriscan_auditlogs(),
        'CoreFiles' => sucuriscan_core_files(),
    );

    echo sucuriscan_get_template('integrity', $template_variables);
}

/**
 * Process the requests sent by the form submissions originated in the integrity
 * page, all forms must have a nonce field that will be checked agains the one
 * generated in the template render function.
 *
 * @return void
 */
function sucuriscan_integrity_form_submissions(){
    if( sucuriscan_check_page_nonce() ){

        // Manually force a filesystem scan (by an administrator user).
        if( isset($_POST['sucuriscan_force_scan']) ){
            if( current_user_can('manage_options') ){
                sucuriscan_notify_event( 'plugin_change', 'Filesystem scan forced at: ' . date('r') );
                sucuriscan_filesystem_scan(TRUE);
            } else {
                sucuriscan_error( 'Your privileges are not sufficient to execute this action.' );
            }
        }

    }
}

/**
 * Retrieve a list of md5sum and last modification time of all the files in the
 * folder specified. This is a recursive function.
 *
 * @param  string  $dir       The base path where the scanning will start.
 * @param  boolean $recursive Either TRUE or FALSE if the scan should be performed recursively.
 * @return array              List of arrays containing the md5sum and last modification time of the files found.
 */
function sucuriscan_get_integrity_tree( $dir='./', $recursive=FALSE ){
    $abs_path = rtrim( ABSPATH, '/' );

    $sucuri_fileinfo = new SucuriScanFileInfo();
    $sucuri_fileinfo->ignore_files = FALSE;
    $sucuri_fileinfo->ignore_directories = FALSE;
    $sucuri_fileinfo->run_recursively = $recursive;
    $integrity_tree = $sucuri_fileinfo->get_directory_tree_md5( $dir, 'opendir', TRUE );

    if( $integrity_tree ){
        return $integrity_tree;
    }

    return FALSE;
}

/**
 * Print a HTML code with the content of the logs audited by the remote Sucuri
 * API service, this page is part of the monitoring tool.
 *
 * @return void
 */
function sucuriscan_auditlogs(){

    // Initialize the values for the pagination.
    $max_per_page = SUCURISCAN_AUDITLOGS_PER_PAGE;
    $page_number = sucuriscan_get_page_number();
    $logs_limit = $page_number * $max_per_page;
    $audit_logs = sucuriscan_get_logs($logs_limit);

    $show_all = TRUE;

    $template_variables = array(
        'PageTitle' => 'Audit Logs',
        'AuditLogs.List' => '',
        'AuditLogs.Count' => 0,
        'AuditLogs.MaxPerPage' => $max_per_page,
        'AuditLogs.NoItemsVisibility' => 'visible',
        'AuditLogs.PaginationVisibility' => 'hidden',
        'AuditLogs.PaginationLinks' => '',
    );

    if( $audit_logs ){
        $counter_i = 0;
        $total_items = count($audit_logs->output_data);
        $offset = 0; // The initial position to start counting the data.

        if( $logs_limit == $total_items ){
            $offset = $logs_limit - ( $max_per_page + 1 );
        }

        for( $i=$offset; $i<$total_items; $i++ ){
            if( $counter_i > $max_per_page ){ break; }

            if( isset($audit_logs->output_data[$i]) ){
                $audit_log = $audit_logs->output_data[$i];

                $css_class = ( $counter_i % 2 == 0 ) ? '' : 'alternate';
                $snippet_data = array(
                    'AuditLog.CssClass' => $css_class,
                    'AuditLog.DateTime' => date( 'd/M/Y H:i:s', $audit_log['timestamp'] ),
                    'AuditLog.Account' => $audit_log['account'],
                    'AuditLog.Message' => $audit_log['message'],
                    'AuditLog.Extra' => '',
                );

                // Print every extra information item in a separate table.
                if( $audit_log['extra'] ){
                    $css_scrollable = $audit_log['extra_total'] > 10 ? 'sucuriscan-list-as-table-scrollable' : '';
                    $snippet_data['AuditLog.Extra'] .= '<ul class="sucuriscan-list-as-table ' . $css_scrollable . '">';
                    foreach( $audit_log['extra'] as $log_extra ){
                        $snippet_data['AuditLog.Extra'] .= '<li>' . $log_extra . '</li>';
                    }
                    $snippet_data['AuditLog.Extra'] .= '</ul>';
                    $snippet_data['AuditLog.Extra'] .= '<small>For Mac users, this is a scrollable container</small>';
                }

                $template_variables['AuditLogs.List'] .= sucuriscan_get_snippet('integrity-auditlogs', $snippet_data);
                $counter_i += 1;
            }
        }

        $template_variables['AuditLogs.Count'] = $counter_i;
        $template_variables['AuditLogs.NoItemsVisibility'] = 'hidden';

        if( $total_items > 0 ){
            $template_variables['AuditLogs.PaginationVisibility'] = 'visible';
            $template_variables['AuditLogs.PaginationLinks'] = sucuriscan_generate_pagination(
                '%%SUCURI.URL.Home%%',
                $max_per_page * 5, /* Temporary value while we get the total logs. */
                $max_per_page
            );
        }
    }

    return sucuriscan_get_section('integrity-auditlogs', $template_variables);
}

/**
 * Check whether the WordPress version is outdated or not.
 *
 * @return string Panel with a warning advising that WordPress is outdated.
 */
function sucuriscan_wordpress_outdated(){
    global $wp_version;

    $updates = get_core_updates();
    $cp = ( !is_array($updates) || empty($updates) ? 1 : 0 );

    $template_variables = array(
        'WordPress.Version' => htmlspecialchars($wp_version),
        'WordPress.UpgradeURL' => admin_url('update-core.php'),
        'WordPress.UpdateVisibility' => 'hidden',
        'WordPressBeta.Visibility' => 'hidden',
        'WordPressBeta.Version' => '0.0.0',
        'WordPressBeta.UpdateURL' => admin_url('update-core.php'),
        'WordPressBeta.DownloadURL' => '#',
    );

    if( isset($updates[0]) && $updates[0] instanceof stdClass ){
        if( $updates[0]->response == 'latest' ){
            $cp = 1;
        }

        elseif( $updates[0]->response == 'development' ){
            $cp = 1;
            $template_variables['WordPressBeta.Visibility'] = 'visible';
            $template_variables['WordPressBeta.Version'] = $updates[0]->version;
            $template_variables['WordPressBeta.DownloadURL'] = $updates[0]->download;
        }
    }

    if( strcmp($wp_version, '3.7') < 0 ){
        $cp = 0;
    }

    if( $cp == 0 ){
        $template_variables['WordPress.UpdateVisibility'] = 'visible';
    }

    return sucuriscan_get_section('integrity-wpoutdate', $template_variables);
}

/**
 * Compare the md5sum of the core files in the current site with the hashes hosted
 * remotely in Sucuri servers. These hashes are updated every time a new version
 * of WordPress is released.
 *
 * @return void
 */
function sucuriscan_core_files(){
    global $wp_version;

    $template_variables = array(
        'CoreFiles.List' => '',
        'CoreFiles.ListCount' => 0,
        'CoreFiles.GoodVisibility' => 'visible',
        'CoreFiles.BadVisibility' => 'hidden',
    );

    if( $wp_version ){
        $latest_hashes = sucuriscan_check_wp_integrity($wp_version);

        if( $latest_hashes ){
            $counter = 0;

            foreach( $latest_hashes as $list_type => $file_list ){
                if(
                    $list_type == 'stable'
                    || empty($file_list)
                ){
                    continue;
                }

                foreach( $file_list as $file_path ){
                    if( $file_path == '.htaccess' ){
                        $file_path = sprintf(
                            '%s <a href="%s" target="_blank">%s</a>',
                            $file_path,
                            '%%SUCURI.URL.Infosys%%#htaccess-integrity',
                            '<em>(Check HTAccess Integrity)</em>'
                        );
                    }

                    elseif( $file_path == 'wp-config.php' ){
                        $file_path = sprintf(
                            '%s <a href="%s" target="_blank">%s</a>',
                            $file_path,
                            '%%SUCURI.URL.Infosys%%#wpconfig-rules',
                            '<em>(Check WP Config Variables)</em>'
                        );
                    }

                    $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                    $template_variables['CoreFiles.List'] .= sucuriscan_get_snippet('integrity-corefiles', array(
                        'CoreFiles.CssClass' => $css_class,
                        'CoreFiles.StatusType' => $list_type,
                        'CoreFiles.StatusAbbr' => substr($list_type, 0, 1),
                        'CoreFiles.FilePath' => $file_path,
                    ));
                    $counter += 1;
                }
            }

            if( $counter > 0 ){
                $template_variables['CoreFiles.ListCount'] = $counter;
                $template_variables['CoreFiles.GoodVisibility'] = 'hidden';
                $template_variables['CoreFiles.BadVisibility'] = 'visible';
            }
        } else {
            sucuriscan_error( 'Error retrieving the WordPress core hashes, try again.' );
        }
    }

    return sucuriscan_get_section('integrity-corefiles', $template_variables);
}

/**
 * Retrieve a list with the checksums of the files in a specific version of WordPress.
 *
 * @see Release Archive http://wordpress.org/download/release-archive/
 *
 * @param  integer $version Valid version number of the WordPress project.
 * @return object           Associative object with the relative filepath and the checksums of the project files.
 */
function sucuriscan_get_official_checksums( $version=0 ){
    $api_url = sprintf('http://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US', $version);
    $request = wp_remote_get($api_url);

    if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
        $json_data = json_decode($request['body']);

        if( $json_data->checksums !== FALSE ){
            $checksums = $json_data->checksums;

            // Convert the object list to an array for better handle of the data.
            if( $checksums instanceof stdClass ){
                $checksums = (array) $checksums;
            }

            return $checksums;
        }
    }

    return FALSE;
}

/**
 * Check whether the core WordPress files where modified, removed or if any file
 * was added to the core folders. This function returns an associative array with
 * these keys:
 *
 * <ul>
 *   <li>modified: Files with a different checksum according to the official files of the WordPress version filtered,</li>
 *   <li>stable: Files with the same checksums than the official files,</li>
 *   <li>removed: Official files which are not present in the local project,</li>
 *   <li>added: Files present in the local project but not in the official WordPress packages.</li>
 * </ul>
 *
 * @param  integer $version Valid version number of the WordPress project.
 * @return array            Associative array with these keys: modified, stable, removed, added.
 */
function sucuriscan_check_wp_integrity( $version=0 ){
    $latest_hashes = sucuriscan_get_official_checksums($version);

    if( !$latest_hashes ){ return FALSE; }

    $output = array(
        'added' => array(),
        'removed' => array(),
        'modified' => array(),
        'stable' => array(),
    );

    // Get current filesystem tree.
    $wp_top_hashes = sucuriscan_get_integrity_tree( ABSPATH , false);
    $wp_admin_hashes = sucuriscan_get_integrity_tree( ABSPATH . 'wp-admin', true);
    $wp_includes_hashes = sucuriscan_get_integrity_tree( ABSPATH . 'wp-includes', true);
    $wp_core_hashes = array_merge( $wp_top_hashes, $wp_admin_hashes, $wp_includes_hashes );

    // Compare remote and local checksums and search removed files.
    foreach( $latest_hashes as $filepath => $remote_checksum ){
        if( sucuriscan_ignore_integrity_filepath($filepath) ){ continue; }

        $full_filepath = sprintf('%s/%s', ABSPATH, $filepath);

        if( file_exists($full_filepath) ){
            $local_checksum = @md5_file($full_filepath);

            if( $local_checksum && $local_checksum == $remote_checksum ){
                $output['stable'][] = $filepath;
            } else {
                $output['modified'][] = $filepath;
            }
        } else {
            $output['removed'][] = $filepath;
        }
    }

    // Search added files (files not common in a normal wordpress installation).
    foreach( $wp_core_hashes as $filepath => $extra_info ){
        $filepath = preg_replace('/^\.\/(.*)/', '$1', $filepath);

        if( sucuriscan_ignore_integrity_filepath($filepath) ){ continue; }

        if( !isset($latest_hashes[$filepath]) ){
            $output['added'][] = $filepath;
        }
    }

    return $output;
}

/**
 * Ignore irrelevant files and directories from the integrity checking.
 *
 * @param  string  $filepath File path that will be compared.
 * @return boolean           TRUE if the file should be ignored, FALSE otherwise.
 */
function sucuriscan_ignore_integrity_filepath( $filepath='' ){
    // List of files that will be ignored from the integrity checking.
    $ignore_files = array(
        'favicon.ico',
        '.htaccess',
        'sitemap.xml',
        'sitemap.xml.gz',
        'wp-config.php',
        'wp-pass.php',
        'wp-rss.php',
        'wp-feed.php',
        'wp-register.php',
        'wp-atom.php',
        'wp-commentsrss2.php',
        'wp-rss2.php',
        'wp-rdf.php',
    );

    if(
        in_array($filepath, $ignore_files)
        || strpos($filepath, 'wp-content/themes') !== FALSE
        || strpos($filepath, 'wp-content/plugins') !== FALSE
    ){
        return TRUE;
    }

    return FALSE;
}

/**
 * List all files inside wp-content that have been modified in the last days.
 *
 * @return void
 */
function sucuriscan_modified_files(){
    $valid_day_ranges = array( 1, 3, 7, 30, 60 );
    $template_variables = array(
        'ModifiedFiles.List' => '',
        'ModifiedFiles.SelectOptions' => '',
        'ModifiedFiles.NoFilesVisibility' => 'visible',
        'ModifiedFiles.Days' => 0,
    );

    // Find files modified in the last days.
    $back_days = 7;

    // Correct the ranges of the search to be between one and sixty days.
    if( sucuriscan_check_page_nonce() && isset($_POST['sucuriscan_last_days']) ){
        $back_days = intval($_POST['sucuriscan_last_days']);
        if    ( $back_days <= 0  ){ $back_days = 1;  }
        elseif( $back_days >= 60 ){ $back_days = 60; }
    }

    // Generate the options for the select field of the page form.
    foreach( $valid_day_ranges as $day ){
        $selected_option = ($back_days == $day) ? 'selected="selected"' : '';
        $template_variables['ModifiedFiles.SelectOptions'] .= sprintf(
            '<option value="%d" %s>%d</option>',
            $day, $selected_option, $day
        );
    }

    // Scan the files of the site.
    $template_variables['ModifiedFiles.Days'] = $back_days;
    $wp_content_hashes = sucuriscan_get_integrity_tree( ABSPATH.'wp-content', true );
    $back_days = current_time('timestamp') - ( $back_days * 86400);
    $counter = 0;

    foreach( $wp_content_hashes as $file_path => $file_info ){
        if( $file_info['filetime'] >= $back_days ){
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
            $mod_date = date('d/M/Y H:i:s', $file_info['filetime']);

            $template_variables['ModifiedFiles.List'] .= sucuriscan_get_snippet('integrity-modifiedfiles', array(
                'ModifiedFiles.CssClass' => $css_class,
                'ModifiedFiles.CheckSum' => $file_info['checksum'],
                'ModifiedFiles.FilePath' => $file_path,
                'ModifiedFiles.DateTime' => $mod_date
            ));
            $counter += 1;
        }
    }

    if( $counter > 0 ){
        $template_variables['ModifiedFiles.NoFilesVisibility'] = 'hidden';
    }

    return sucuriscan_get_section('integrity-modifiedfiles', $template_variables);
}

/**
 * Generate and print the HTML code for the Post-Hack page.
 *
 * @return void
 */
function sucuriscan_posthack_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Post-Hack') );
    }

    $process_form = sucuriscan_posthack_process_form();

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PageTitle' => 'Post-Hack',
        'UpdateSecretKeys' => sucuriscan_update_secret_keys($process_form),
        'ResetPassword' => sucuriscan_posthack_users($process_form),
        'ResetPlugins' => sucuriscan_posthack_plugins($process_form),
    );

    echo sucuriscan_get_template('posthack', $template_variables);
}

/**
 * Check whether the "I understand this operation" checkbox was marked or not.
 *
 * @return boolean TRUE if a form submission should be processed, FALSE otherwise.
 */
function sucuriscan_posthack_process_form(){
    if( sucuriscan_check_page_nonce() && isset($_POST['sucuriscan_process_form']) ){
        if( $_POST['sucuriscan_process_form'] == 1 ){
            return TRUE;
        } else {
            sucuriscan_error('You need to confirm that you understand the risk of this operation.');
        }
    }

    return FALSE;
}

/**
 * Update the WordPress secret keys.
 *
 * @param  $process_form Whether a form was submitted or not.
 * @return string        HTML code with the information of the process.
 */
function sucuriscan_update_secret_keys( $process_form=FALSE ){
    $template_variables = array(
        'WPConfigUpdate.Visibility' => 'hidden',
        'WPConfigUpdate.NewConfig' => '',
    );

    // Update all WordPress secret keys.
    if( $process_form && isset($_POST['sucuriscan_update_wpconfig']) ){
        $wpconfig_process = sucuriscan_set_new_config_keys();

        if( $wpconfig_process ){
            $template_variables['WPConfigUpdate.Visibility'] = 'visible';

            if( $wpconfig_process['updated'] === TRUE ){
                sucuriscan_info( 'WordPress secret keys updated successfully (check bellow the summary of the operation).' );
                $template_variables['WPConfigUpdate.NewConfig'] .= "// Old Keys\n";
                $template_variables['WPConfigUpdate.NewConfig'] .= $wpconfig_process['old_keys_string'];
                $template_variables['WPConfigUpdate.NewConfig'] .= "//\n";
                $template_variables['WPConfigUpdate.NewConfig'] .= "// New Keys\n";
                $template_variables['WPConfigUpdate.NewConfig'] .= $wpconfig_process['new_keys_string'];
            } else {
                sucuriscan_error( '<code>wp-config.php</code> file is not writable, replace the old configuration file with the new values shown bellow.' );
                $template_variables['WPConfigUpdate.NewConfig'] = $wpconfig_process['new_wpconfig'];
            }
        } else {
            sucuriscan_error('<code>wp-config.php</code> file was not found in the default location.' );
        }
    }

    return sucuriscan_get_section('posthack-updatesecretkeys', $template_variables);
}

/**
 * Display a list of users in a table that will be used to select the accounts
 * where a password reset action will be executed.
 *
 * @param  $process_form Whether a form was submitted or not.
 * @return string        HTML code for a table where a list of user accounts will be shown.
 */
function sucuriscan_posthack_users( $process_form=FALSE ){
    $template_variables = array(
        'ResetPassword.UserList' => '',
    );

    // Process the form submission (if any).
    sucuriscan_reset_user_password($process_form);

    // Fill the user list for ResetPassword action.
    $user_list = get_users();

    if( $user_list ){
        $counter = 0;

        foreach( $user_list as $user ){
            $user->user_registered_timestamp = strtotime($user->user_registered);
            $user->user_registered_formatted = date('D, M/Y H:i', $user->user_registered_timestamp);
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

            $user_snippet = sucuriscan_get_snippet('posthack-resetpassword', array(
                'ResetPassword.UserId' => $user->ID,
                'ResetPassword.Username' => $user->user_login,
                'ResetPassword.Displayname' => $user->display_name,
                'ResetPassword.Email' => $user->user_email,
                'ResetPassword.Registered' => $user->user_registered_formatted,
                'ResetPassword.Roles' => implode(', ', $user->roles),
                'ResetPassword.CssClass' => $css_class
            ));

            $template_variables['ResetPassword.UserList'] .= $user_snippet;
            $counter += 1;
        }
    }

    return sucuriscan_get_section('posthack-resetpassword', $template_variables);
}

/**
 * Update the password of the user accounts specified.
 *
 * @param  $process_form Whether a form was submitted or not.
 * @return void
 */
function sucuriscan_reset_user_password( $process_form=FALSE ){
    if( $process_form && isset($_POST['sucuriscan_reset_password']) ){
        $user_identifiers = isset($_POST['user_ids']) ? $_POST['user_ids'] : array();
        $pwd_changed = $pwd_not_changed = array();

        if( is_array($user_identifiers) && !empty($user_identifiers) ){
            arsort($user_identifiers);

            foreach( $user_identifiers as $user_id ){
                if( sucuriscan_new_password($user_id) ){
                    $pwd_changed[] = $user_id;
                } else {
                    $pwd_not_changed[] = $user_id;
                }
            }

            if( !empty($pwd_changed) ){
                sucuriscan_info( 'Password changed successfully for users: ' . implode(', ',$pwd_changed) );
            }

            if( !empty($pwd_not_changed) ){
                sucuriscan_error( 'Password change failed for users: ' . implode(', ',$pwd_not_changed) );
            }
        } else {
            sucuriscan_error( 'You did not select a user from the list.' );
        }
    }
}

/**
 * Reset all the FREE plugins, even if they are not activated.
 *
 * @param  boolean $process_form Whether a form was submitted or not.
 * @return void
 */
function sucuriscan_posthack_plugins( $process_form=FALSE ){
    $template_variables = array(
        'ResetPlugin.PluginList' => '',
    );

    sucuriscan_posthack_reinstall_plugins($process_form);
    $all_plugins = sucuriscan_get_plugins();
    $counter = 0;

    foreach( $all_plugins as $plugin_path => $plugin_data ){
        $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
        $plugin_type_class = ( $plugin_data['PluginType'] == 'free' ) ? 'primary' : 'warning';
        $input_disabled = ( $plugin_data['PluginType'] == 'free' ) ? '' : 'disabled="disabled"';
        $plugin_status = $plugin_data['IsPluginActive'] ? 'active' : 'not active';
        $plugin_status_class = $plugin_data['IsPluginActive'] ? 'success' : 'default';

        $template_variables['ResetPlugin.PluginList'] .= sucuriscan_get_snippet('posthack-resetplugins', array(
            'ResetPlugin.CssClass' => $css_class,
            'ResetPlugin.Disabled' => $input_disabled,
            'ResetPlugin.PluginPath' => $plugin_path,
            'ResetPlugin.Plugin' => sucuriscan_excerpt($plugin_data['Name'], 35),
            'ResetPlugin.Version' => $plugin_data['Version'],
            'ResetPlugin.Type' => $plugin_data['PluginType'],
            'ResetPlugin.TypeClass' => $plugin_type_class,
            'ResetPlugin.Status' => $plugin_status,
            'ResetPlugin.StatusClass' => $plugin_status_class,
        ));

        $counter += 1;
    }

    return sucuriscan_get_section('posthack-resetplugins', $template_variables);
}

/**
 * Process the request that will start the execution of the plugin
 * reinstallation, it will check if the plugins submitted are (in fact)
 * installed in the system, then check if they are free download from the
 * WordPress market place, and finally download and install them.
 *
 * @param  boolean $process_form Whether a form was submitted or not.
 * @return void
 */
function sucuriscan_posthack_reinstall_plugins( $process_form=FALSE ){
    if( $process_form && isset($_POST['sucuriscan_reset_plugins']) ){
        include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
        include_once( ABSPATH . 'wp-admin/includes/plugin-install.php' ); // For plugins_api.

        if(
            isset($_POST['plugin_path'])
            && !empty($_POST['plugin_path'])
        ){
            // Create an instance of the FileInfo interface.
            $sucuri_fileinfo = new SucuriScanFileInfo();
            $sucuri_fileinfo->ignore_files = FALSE;
            $sucuri_fileinfo->ignore_directories = FALSE;

            // Get (possible) cached information from the installed plugins.
            $all_plugins = sucuriscan_get_plugins();

            // Loop through all the installed plugins.
            foreach( $_POST['plugin_path'] as $plugin_path ){
                if( array_key_exists($plugin_path, $all_plugins) ){
                    $plugin_data = $all_plugins[$plugin_path];

                    // Check if the plugin can be downloaded from the free market.
                    if( $plugin_data['IsFreePlugin'] === TRUE ){
                        $plugin_info = sucuriscan_get_remote_plugin_data($plugin_data['RepositoryName']);

                        if( $plugin_info ){
                            // First, remove all files/sub-folders from the plugin's directory.
                            $plugin_directory = dirname( WP_PLUGIN_DIR . '/' . $plugin_path );
                            $sucuri_fileinfo->remove_directory_tree($plugin_directory);

                            // Install a fresh copy of the plugin's files.
                            $upgrader_skin = new Plugin_Installer_Skin();
                            $upgrader = new Plugin_Upgrader($upgrader_skin);
                            $upgrader->install($plugin_info->download_link);
                        } else {
                            sucuriscan_error( 'Could not establish a stable connection with the WordPress plugins market.' );
                        }
                    }
                }
            }
        } else {
            sucuriscan_error( 'You did not select a free plugin to reinstall.' );
        }
    }
}

/**
 * Generate and print the HTML code for the Last Logins page.
 *
 * This page will contains information of all the logins of the registered users.
 *
 * @return string Last-logings for the administrator accounts.
 */
function sucuriscan_lastlogins_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PageTitle' => 'Last Logins',
        'LastLogins.Admins' => sucuriscan_lastlogins_admins(),
        'LastLogins.AllUsers' => sucuriscan_lastlogins_all(),
        'LoggedInUsers' => sucuriscan_loggedin_users_panel(),
        'FailedLogins' => sucuriscan_failed_logins_panel(),
    );

    echo sucuriscan_get_template('lastlogins', $template_variables);
}

/**
 * List all the user administrator accounts.
 *
 * @see http://codex.wordpress.org/Class_Reference/WP_User_Query
 *
 * @return void
 */
function sucuriscan_lastlogins_admins(){
    // Page pseudo-variables initialization.
    $template_variables = array(
        'AdminUsers.List' => ''
    );

    $user_query = new WP_User_Query(array( 'role' => 'Administrator' ));
    $admins = $user_query->get_results();

    foreach( (array) $admins as $admin ){
        $last_logins = sucuriscan_get_logins(5, 0, $admin->ID);
        $admin->lastlogins = $last_logins['entries'];

        $user_snippet = array(
            'AdminUsers.Username' => $admin->user_login,
            'AdminUsers.Email' => $admin->user_email,
            'AdminUsers.LastLogins' => '',
            'AdminUsers.RegisteredAt' => 'Undefined',
            'AdminUsers.UserURL' => admin_url('user-edit.php?user_id='.$admin->ID),
            'AdminUsers.NoLastLogins' => 'visible',
            'AdminUsers.NoLastLoginsTable' => 'hidden',
        );

        if( !empty($admin->lastlogins) ){
            $user_snippet['AdminUsers.NoLastLogins'] = 'hidden';
            $user_snippet['AdminUsers.NoLastLoginsTable'] = 'visible';
            $user_snippet['AdminUsers.RegisteredAt'] = $admin->user_registered;
            $counter = 0;

            foreach( $admin->lastlogins as $lastlogin ){
                $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';
                $user_snippet['AdminUsers.LastLogins'] .= sucuriscan_get_snippet('lastlogins-admins-lastlogin', array(
                    'AdminUsers.RemoteAddr' => $lastlogin->user_remoteaddr,
                    'AdminUsers.Datetime' => $lastlogin->user_lastlogin,
                    'AdminUsers.CssClass' => $css_class,
                ));
                $counter += 1;
            }
        }

        $template_variables['AdminUsers.List'] .= sucuriscan_get_snippet('lastlogins-admins', $user_snippet);
    }

    return sucuriscan_get_section('lastlogins-admins', $template_variables);
}

/**
 * List the last-logins for all user accounts in the site.
 *
 * This page will contains information of all the logins of the registered users.
 *
 * @return string Last-logings for all user accounts.
 */
function sucuriscan_lastlogins_all(){
    $max_per_page = SUCURISCAN_LASTLOGINS_USERSLIMIT;
    $page_number = sucuriscan_get_page_number();
    $offset = ($max_per_page * $page_number) - $max_per_page;

    $template_variables = array(
        'UserList' => '',
        'UserList.Limit' => $max_per_page,
        'UserList.Total' => 0,
        'UserList.Pagination' => '',
        'UserList.PaginationVisibility' => 'hidden',
        'UserList.NoItemsVisibility' => 'visible',
    );

    if( !sucuriscan_lastlogins_datastore_is_writable() ){
        sucuriscan_error( 'Last-logins datastore file is not writable: <code>'.sucuriscan_lastlogins_datastore_filepath().'</code>' );
    }

    $counter = 0;
    $last_logins = sucuriscan_get_logins( $max_per_page, $offset );
    $template_variables['UserList.Total'] = $last_logins['total'];

    if( $last_logins['total'] > $max_per_page ){
        $template_variables['UserList.PaginationVisibility'] = 'visible';
        $template_variables['UserList.NoItemsVisibility'] = 'hidden';
    }

    foreach( $last_logins['entries'] as $user ){
        $counter += 1;
        $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';

        $user_dataset = array(
            'UserList.Number' => $user->line_num,
            'UserList.UserId' => $user->user_id,
            'UserList.Username' => '<em>Unknown</em>',
            'UserList.Displayname' => '',
            'UserList.Email' => '',
            'UserList.Registered' => '',
            'UserList.RemoteAddr' => $user->user_remoteaddr,
            'UserList.Hostname' => $user->user_hostname,
            'UserList.Datetime' => $user->user_lastlogin,
            'UserList.TimeAgo' => sucuriscan_time_ago($user->user_lastlogin),
            'UserList.UserURL' => admin_url('user-edit.php?user_id='.$user->user_id),
            'UserList.CssClass' => $css_class,
        );

        if( $user->user_exists ){
            $user_dataset['UserList.Username'] = $user->user_login;
            $user_dataset['UserList.Displayname'] = $user->display_name;
            $user_dataset['UserList.Email'] = $user->user_email;
            $user_dataset['UserList.Registered'] = $user->user_registered;
        }

        $template_variables['UserList'] .= sucuriscan_get_snippet('lastlogins-all', $user_dataset);
    }

    // Generate the pagination for the list.
    $template_variables['UserList.Pagination'] = sucuriscan_generate_pagination(
        '%%SUCURI.URL.Lastlogins%%',
        $last_logins['total'],
        $max_per_page
    );

    return sucuriscan_get_section('lastlogins-all', $template_variables);
}

/**
 * Get the filepath where the information of the last logins of all users is stored.
 *
 * @return string Absolute filepath where the user's last login information is stored.
 */
function sucuriscan_lastlogins_datastore_filepath(){
    return sucuriscan_dir_filepath( 'sucuri-lastlogins.php' );
}

/**
 * Check whether the user's last login datastore file exists or not, if not then
 * we try to create the file and check again the success of the operation.
 *
 * @return string Absolute filepath where the user's last login information is stored.
 */
function sucuriscan_lastlogins_datastore_exists(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_filepath();

    if( !file_exists($datastore_filepath) ){
        if( @file_put_contents($datastore_filepath, "<?php exit(0); ?>\n", LOCK_EX) ){
            @chmod($datastore_filepath, 0644);
        }
    }

    return file_exists($datastore_filepath) ? $datastore_filepath : FALSE;
}

/**
 * Check whether the user's last login datastore file is writable or not, if not
 * we try to set the right permissions and check again the success of the operation.
 *
 * @return boolean Whether the user's last login datastore file is writable or not.
 */
function sucuriscan_lastlogins_datastore_is_writable(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_exists();
    if($datastore_filepath){
        if( !is_writable($datastore_filepath) ){
            @chmod($datastore_filepath, 0644);
        }
        return is_writable($datastore_filepath) ? $datastore_filepath : FALSE;
    }
    return FALSE;
}

/**
 * Check whether the user's last login datastore file is readable or not, if not
 * we try to set the right permissions and check again the success of the operation.
 *
 * @return boolean Whether the user's last login datastore file is readable or not.
 */
function sucuriscan_lastlogins_datastore_is_readable(){
    $datastore_filepath = sucuriscan_lastlogins_datastore_exists();
    if( $datastore_filepath && is_readable($datastore_filepath) ){
        return $datastore_filepath;
    }
    return FALSE;
}

if( !function_exists('sucuri_set_lastlogin') ){
    /**
     * Add a new user session to the list of last user logins.
     *
     * @param  string $user_login The name of the user account involved in the operation.
     * @return void
     */
    function sucuriscan_set_lastlogin($user_login=''){
        $datastore_filepath = sucuriscan_lastlogins_datastore_is_writable();

        if($datastore_filepath){
            $current_user = get_user_by('login', $user_login);
            $remote_addr = sucuriscan_get_remoteaddr();

            $login_info = array(
                'user_id' => $current_user->ID,
                'user_login' => $current_user->user_login,
                'user_remoteaddr' => $remote_addr,
                'user_hostname' => @gethostbyaddr($remote_addr),
                'user_lastlogin' => current_time('mysql')
            );

            @file_put_contents($datastore_filepath, serialize($login_info)."\n", FILE_APPEND);
        }
    }
    add_action('wp_login', 'sucuriscan_set_lastlogin', 50);
}

/**
 * Retrieve the list of all the user logins from the datastore file.
 *
 * The results of this operation can be filtered by specific user identifiers,
 * or limiting the quantity of entries.
 *
 * @param  integer $limit   How many entries will be returned from the operation.
 * @param  integer $offset  Initial point where the logs will be start counting.
 * @param  integer $user_id Optional user identifier to filter the results.
 * @return array            The list of all the user logins, and total of entries registered.
 */
function sucuriscan_get_logins( $limit=10, $offset=0, $user_id=0 ){
    $datastore_filepath = sucuriscan_lastlogins_datastore_is_readable();
    $last_logins = array(
        'total' => 0,
        'entries' => array(),
    );

    if( $datastore_filepath ){
        $parsed_lines = 0;
        $data_lines = @file($datastore_filepath);

        if( $data_lines ){
            /**
             * This count will not be 100% accurate considering that we are checking the
             * syntax of each line in the loop bellow, there may be some lines without the
             * right syntax which will differ from the total entries returned, but there's
             * not other EASY way to do this without affect the performance of the code.
             *
             * @var integer
             */
            $total_lines = count($data_lines);
            $last_logins['total'] = $total_lines;

            // Get a list with the latest entries in the first positions.
            $reversed_lines = array_reverse($data_lines);

            /**
             * Only the user accounts with administrative privileges can see the logs of all
             * the users, for the rest of the accounts they will only see their own logins.
             *
             * @var object
             */
            $current_user = wp_get_current_user();
            $is_admin_user = (bool) current_user_can('manage_options');

            for( $i=$offset; $i<$total_lines; $i++ ){
                $line = $reversed_lines[$i] ? trim($reversed_lines[$i]) : '';

                if( preg_match('/^a:/', $line) ){
                    $last_login = @unserialize($line);

                    // Only administrators can see all login stats.
                    if( !$is_admin_user && $current_user->user_login != $last_login['user_login'] ){
                        continue;
                    }

                    // Filter the user identifiers using the value passed tot his function.
                    if( $user_id > 0 && $last_login['user_id'] != $user_id ){
                        continue;
                    }

                    // Get the WP_User object and add extra information from the last-login data.
                    $last_login['user_exists'] = FALSE;
                    $user_account = get_userdata($last_login['user_id']);

                    if( $user_account ){
                        $last_login['user_exists'] = TRUE;

                        foreach( $user_account->data as $var_name=>$var_value ){
                            $last_login[$var_name] = $var_value;
                        }
                    }

                    $last_login['line_num'] = $i + 1;
                    $last_logins['entries'][] = (object) $last_login;
                    $parsed_lines += 1;
                }

                if( preg_match('/^([0-9]+)$/', $limit) && $limit>0 ){
                    if( $parsed_lines >= $limit ){ break; }
                }
            }
        }
    }

    return $last_logins;
}

if( !function_exists('sucuri_login_redirect') ){
    /**
     * Hook for the wp-login action to redirect the user to a specific URL after
     * his successfully login to the administrator interface.
     *
     * @param  string  $redirect_to URL where the browser must be originally redirected to, set by WordPress itself.
     * @param  object  $request     Optional parameter set by WordPress itself through the event triggered.
     * @param  boolean $user        WordPress user object with the information of the account involved in the operation.
     * @return string               URL where the browser must be redirected to.
     */
    function sucuriscan_login_redirect( $redirect_to='', $request=NULL, $user=FALSE ){
        $login_url = !empty($redirect_to) ? $redirect_to : admin_url();

        if( $user instanceof WP_User && $user->ID ){
            $login_url = add_query_arg( 'sucuriscan_lastlogin', 1, $login_url );
        }

        return $login_url;
    }

    $lastlogin_redirection = sucuriscan_get_option('sucuriscan_lastlogin_redirection');
    if( $lastlogin_redirection == 'enabled' ){
        add_filter('login_redirect', 'sucuriscan_login_redirect', 10, 3);
    }
}

if( !function_exists('sucuri_get_user_lastlogin') ){
    /**
     * Display the last user login at the top of the admin interface.
     *
     * @return void
     */
    function sucuriscan_get_user_lastlogin(){
        if( isset($_GET['sucuriscan_lastlogin']) && current_user_can('manage_options') ){
            $current_user = wp_get_current_user();

            // Select the penultimate entry, not the last one.
            $last_logins = sucuriscan_get_logins(2, 0, $current_user->ID);

            if( isset($last_logins['entries'][1]) ){
                $row = $last_logins['entries'][1];

                $message_tpl  = 'Last time you logged in was at <code>%s</code> from <code>%s</code> - <code>%s</code>';
                $lastlogin_message = sprintf( $message_tpl, date('d/M/Y H:i'), $row->user_remoteaddr, $row->user_hostname );
                $lastlogin_message .= chr(32).'(<a href="'.site_url('wp-admin/admin.php?page='.SUCURISCAN.'_lastlogins').'">view all logs</a>)';
                sucuriscan_info( $lastlogin_message );
            }
        }
    }

    add_action('admin_notices', 'sucuriscan_get_user_lastlogin');
}

/**
 * Print a list of all the registered users that are currently in session.
 *
 * @return string The HTML code displaying a list of all the users logged in at the moment.
 */
function sucuriscan_loggedin_users_panel(){
    // Get user logged in list.
    $template_variables = array(
        'LoggedInUsers.List' => '',
        'LoggedInUsers.Total' => 0,
    );

    $logged_in_users = sucuriscan_get_online_users(TRUE);
    if( is_array($logged_in_users) && !empty($logged_in_users) ){
        $template_variables['LoggedInUsers.Total'] = count($logged_in_users);
        $counter = 0;

        foreach( (array) $logged_in_users as $logged_in_user ){
            $counter += 1;
            $logged_in_user['last_activity_datetime'] = date('d/M/Y H:i', $logged_in_user['last_activity']);
            $logged_in_user['user_registered_datetime'] = date('d/M/Y H:i', strtotime($logged_in_user['user_registered']));

            $template_variables['LoggedInUsers.List'] .= sucuriscan_get_snippet('lastlogins-loggedin', array(
                'LoggedInUsers.Id' => $logged_in_user['user_id'],
                'LoggedInUsers.UserURL' => admin_url('user-edit.php?user_id='.$logged_in_user['user_id']),
                'LoggedInUsers.UserLogin' => $logged_in_user['user_login'],
                'LoggedInUsers.UserEmail' => $logged_in_user['user_email'],
                'LoggedInUsers.LastActivity' => $logged_in_user['last_activity_datetime'],
                'LoggedInUsers.Registered' => $logged_in_user['user_registered_datetime'],
                'LoggedInUsers.RemoveAddr' => $logged_in_user['remote_addr'],
                'LoggedInUsers.CssClass' => ( $counter % 2 == 0 ) ? '' : 'alternate'
            ));
        }
    }

    return sucuriscan_get_section('lastlogins-loggedin', $template_variables);
}

/**
 * Get a list of all the registered users that are currently in session.
 *
 * @param  boolean $add_current_user Whether the current user should be added to the list or not.
 * @return array                     List of registered users currently in session.
 */
function sucuriscan_get_online_users( $add_current_user=FALSE ){
    $users = array();

    if( sucuriscan_is_multisite() ){
        $users = get_site_transient('online_users');
    } else {
        $users = get_transient('online_users');
    }

    // If not online users but current user is logged in, add it to the list.
    if( empty($users) && $add_current_user ){
        $current_user = wp_get_current_user();

        if( $current_user->ID > 0 ){
            sucuriscan_set_online_user( $current_user->user_login, $current_user );

            return sucuriscan_get_online_users();
        }
    }

    return $users;
}

/**
 * Update the list of the registered users currently in session.
 *
 * Useful when you are removing users and need the list of the remaining users.
 *
 * @param  array   $logged_in_users List of registered users currently in session.
 * @return boolean                  Either TRUE or FALSE representing the success or fail of the operation.
 */
function sucuriscan_save_online_users( $logged_in_users=array() ){
    $expiration = 30 * 60;

    if( sucuriscan_is_multisite() ){
        return set_site_transient('online_users', $logged_in_users, $expiration);
    } else {
        return set_transient('online_users', $logged_in_users, $expiration);
    }
}

if( !function_exists('sucuriscan_unset_online_user_on_logout') ){
    /**
     * Remove a logged in user from the list of registered users in session when
     * the logout page is requested.
     *
     * @return void
     */
    function sucuriscan_unset_online_user_on_logout(){
        $remote_addr = sucuriscan_get_remoteaddr();
        $current_user = wp_get_current_user();
        $user_id = $current_user->ID;

        sucuriscan_unset_online_user($user_id, $remote_addr);
    }

    add_action('wp_logout', 'sucuriscan_unset_online_user_on_logout');
}

/**
 * Remove a logged in user from the list of registered users in session using
 * the user identifier and the ip address of the last computer used to login.
 *
 * @param  integer $user_id     User identifier of the account that will be logged out.
 * @param  integer $remote_addr IP address of the computer where the user logged in.
 * @return boolean              Either TRUE or FALSE representing the success or fail of the operation.
 */
function sucuriscan_unset_online_user( $user_id=0, $remote_addr=0 ){
    $logged_in_users = sucuriscan_get_online_users();

    // Remove the specified user identifier from the list.
    if( is_array($logged_in_users) && !empty($logged_in_users) ){
        foreach( $logged_in_users as $i => $user ){
            if(
                $user['user_id']==$user_id
                && strcmp($user['remote_addr'], $remote_addr) == 0
            ){
                unset($logged_in_users[$i]);
                break;
            }
        }
    }

    return sucuriscan_save_online_users($logged_in_users);
}

if( !function_exists('sucuriscan_set_online_user') ){
    /**
     * Add an user account to the list of registered users in session.
     *
     * @param  string  $user_login The name of the user account that just logged in the site.
     * @param  boolean $user       The WordPress object containing all the information associated to the user.
     * @return void
     */
    function sucuriscan_set_online_user( $user_login='', $user=FALSE ){
        if( $user ){
            // Get logged in user information.
            $current_user = ($user instanceof WP_User) ? $user : wp_get_current_user();
            $current_user_id = $current_user->ID;
            $remote_addr = sucuriscan_get_remoteaddr();
            $current_time = current_time('timestamp');
            $logged_in_users = sucuriscan_get_online_users();

            // Build the dataset array that will be stored in the transient variable.
            $current_user_info = array(
                'user_id' => $current_user_id,
                'user_login' => $current_user->user_login,
                'user_email' => $current_user->user_email,
                'user_registered' => $current_user->user_registered,
                'last_activity' => $current_time,
                'remote_addr' => $remote_addr
            );

            if( !is_array($logged_in_users) || empty($logged_in_users) ){
                $logged_in_users = array( $current_user_info );
                sucuriscan_save_online_users($logged_in_users);
            } else {
                $do_nothing = FALSE;
                $update_existing = FALSE;
                $item_index = 0;

                // Check if the user is already in the logged-in-user list and update it if is necessary.
                foreach( $logged_in_users as $i => $user ){
                    if(
                        $user['user_id'] == $current_user_id
                        && strcmp($user['remote_addr'], $remote_addr) == 0
                    ){
                        if( $user['last_activity'] < ($current_time - (15 * 60)) ){
                            $update_existing = TRUE;
                            $item_index = $i;
                            break;
                        } else {
                            $do_nothing = TRUE;
                            break;
                        }
                    }
                }

                if( $update_existing ){
                    $logged_in_users[$item_index] = $current_user_info;
                    sucuriscan_save_online_users($logged_in_users);
                } elseif($do_nothing){
                    // Do nothing.
                } else {
                    $logged_in_users[] = $current_user_info;
                    sucuriscan_save_online_users($logged_in_users);
                }
            }
        }
    }

    add_action('wp_login', 'sucuriscan_set_online_user', 10, 2);
}

/**
 * Print a list with the failed logins occurred during the last hour.
 *
 * @return string A list with the failed logins occurred during the last hour.
 */
function sucuriscan_failed_logins_panel(){
    $template_variables = array(
        'FailedLogins.List' => '',
        'FailedLogins.Total' => '',
        'FailedLogins.MaxFailedLogins' => 0,
        'FailedLogins.NoItemsVisibility' => 'visible',
        'FailedLogins.WarningVisibility' => 'visible',
    );

    $max_failed_logins = sucuriscan_get_option('sucuriscan_maximum_failed_logins');
    $notify_bruteforce_attack = sucuriscan_get_option('sucuriscan_notify_bruteforce_attack');
    $failed_logins = sucuriscan_get_failed_logins();

    if( $failed_logins ){
        $counter = 0;

        foreach( $failed_logins['entries'] as $login_data ){
            $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

            $template_variables['FailedLogins.List'] .= sucuriscan_get_snippet('lastlogins-failedlogins', array(
                'FailedLogins.CssClass' => $css_class,
                'FailedLogins.Num' => ($counter + 1),
                'FailedLogins.Username' => $login_data['user_login'],
                'FailedLogins.RemoteAddr' => $login_data['remote_addr'],
                'FailedLogins.Datetime' => date('d/M/Y H:i', $login_data['attempt_time']),
                'FailedLogins.UserAgent' => esc_attr($login_data['user_agent']),
            ));

            $counter += 1;
        }

        if( $counter > 0 ){
            $template_variables['FailedLogins.NoItemsVisibility'] = 'hidden';
        }
    }

    $template_variables['FailedLogins.MaxFailedLogins'] = $max_failed_logins;

    if( $notify_bruteforce_attack == 'enabled' ){
        $template_variables['FailedLogins.WarningVisibility'] = 'hidden';
    }

    return sucuriscan_get_section('lastlogins-failedlogins', $template_variables);
}

/**
 * Find the full path of the file where the information of the failed logins
 * will be stored, it will be created automatically if does not exists (and if
 * the destination folder has permissions to write). This function can also be
 * used to reset the content of the datastore file.
 *
 * @see sucuriscan_reset_failed_logins()
 *
 * @param  boolean $reset Whether the file will be resetted or not.
 * @return string         The full (relative) path where the file is located.
 */
function sucuriscan_failed_logins_datastore_path( $reset=FALSE ){
    $datastore_path = sucuriscan_dir_filepath('sucuri-failedlogins.php');
    $default_content = sucuriscan_failed_logins_default_content();

    // Create the file if it does not exists.
    if( !file_exists($datastore_path) || $reset ){
        @file_put_contents( $datastore_path, $default_content, LOCK_EX );
    }

    // Return the datastore path if the file exists (or was created).
    if(
        file_exists($datastore_path)
        && is_readable($datastore_path)
    ){
        return $datastore_path;
    }

    return FALSE;
}

/**
 * Default content of the datastore file where the failed logins are being kept.
 *
 * @return string Default content of the file.
 */
function sucuriscan_failed_logins_default_content(){
    $default_content = "<?php exit(0); ?>\n";

    return $default_content;
}

/**
 * Read and parse the content of the datastore file where the failed logins are
 * being kept. This function will also calculate the difference in time between
 * the first and last login attempt registered in the file to later decide if
 * there is a brute-force attack in progress (and send an email notification
 * with the report) or reset the file after considering it a normal behavior of
 * the site.
 *
 * @return array Information and entries gathered from the failed logins datastore file.
 */
function sucuriscan_get_failed_logins(){
    $datastore_path = sucuriscan_failed_logins_datastore_path();
    $default_content = sucuriscan_failed_logins_default_content();
    $default_content_n = substr_count($default_content, "\n");

    if( $datastore_path ){
        $lines = @file($datastore_path);

        if( $lines ){
            $failed_logins = array(
                'count' => 0,
                'first_attempt' => 0,
                'last_attempt' => 0,
                'diff_time' => 0,
                'entries' => array(),
            );

            // Read and parse all the entries found in the datastore file.
            foreach( $lines as $i => $line ){
                if( $i >= $default_content_n ){
                    $login_data = json_decode( trim($line), TRUE );
                    $login_data['attempt_date'] = date('r', $login_data['attempt_time']);

                    if( !$login_data['user_agent'] ){
                        $login_data['user_agent'] = 'Unknown';
                    }

                    $failed_logins['entries'][] = $login_data;
                    $failed_logins['count'] += 1;
                }
            }

            // Calculate the different time between the first and last attempt.
            if( $failed_logins['count'] > 0 ){
                $z = abs($failed_logins['count'] - 1);
                $failed_logins['last_attempt'] = $failed_logins['entries'][$z]['attempt_time'];
                $failed_logins['first_attempt'] = $failed_logins['entries'][0]['attempt_time'];
                $failed_logins['diff_time'] = abs( $failed_logins['last_attempt'] - $failed_logins['first_attempt'] );

                return $failed_logins;
            }
        }
    }

    return FALSE;
}


/**
 * Add a new entry in the datastore file where the failed logins are being kept,
 * this entry will contain the username, timestamp of the login attempt, remote
 * address of the computer sending the request, and the user-agent.
 *
 * @param  string  $user_login Information from the current failed login event.
 * @return boolean             Whether the information of the current failed login event was stored or not.
 */
function sucuriscan_log_failed_login( $user_login='' ){
    $datastore_path = sucuriscan_failed_logins_datastore_path();

    if( $datastore_path ){
        $login_data = json_encode(array(
            'user_login' => $user_login,
            'attempt_time' => time(),
            'remote_addr' => sucuriscan_get_remoteaddr(),
            'user_agent' => sucuriscan_get_useragent(),
        ));

        $logged = @file_put_contents( $datastore_path, $login_data . "\n", FILE_APPEND );

        return $logged;
    }

    return FALSE;
}

/**
 * Read and parse all the entries in the datastore file where the failed logins
 * are being kept, this will loop through all these items and generate a table
 * in HTML code to send as a report via email according to the plugin settings
 * for the email notifications.
 *
 * @param  array   $failed_logins Information and entries gathered from the failed logins datastore file.
 * @return boolean                Whether the report was sent via email or not.
 */
function sucuriscan_report_failed_logins( $failed_logins=array() ){
    if( $failed_logins && $failed_logins['count'] > 0 ){
        $prettify_mails = sucuriscan_prettify_mails();
        $mail_content = '';

        if( $prettify_mails ){
            $table_html  = '<table border="1" cellspacing="0" cellpadding="0">';

            // Add the table headers.
            $table_html .= '<thead>';
            $table_html .= '<tr>';
            $table_html .= '<th>Username</th>';
            $table_html .= '<th>IP Address</th>';
            $table_html .= '<th>Attempt Timestamp</th>';
            $table_html .= '<th>Attempt Date/Time</th>';
            $table_html .= '</tr>';
            $table_html .= '</thead>';

            $table_html .= '<tbody>';
        }

        foreach( $failed_logins['entries'] as $login_data ){
            if( $prettify_mails ){
                $table_html .= '<tr>';
                $table_html .= '<td>' . esc_attr($login_data['user_login']) . '</td>';
                $table_html .= '<td>' . esc_attr($login_data['remote_addr']) . '</td>';
                $table_html .= '<td>' . $login_data['attempt_time'] . '</td>';
                $table_html .= '<td>' . $login_data['attempt_date'] . '</td>';
                $table_html .= '</tr>';
            } else {
                $mail_content .= "\n";
                $mail_content .= 'Username: ' . $login_data['user_login'] . "\n";
                $mail_content .= 'IP Address: ' . $login_data['remote_addr'] . "\n";
                $mail_content .= 'Attempt Timestamp: ' . $login_data['attempt_time'] . "\n";
                $mail_content .= 'Attempt Date/Time: ' . $login_data['attempt_date'] . "\n";
            }
        }

        if( $prettify_mails ){
            $table_html .= '</tbody>';
            $table_html .= '</table>';
            $mail_content = $table_html;
        }

        if( sucuriscan_notify_event( 'bruteforce_attack', $mail_content ) ){
            sucuriscan_reset_failed_logins();

            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Remove all the entries in the datastore file where the failed logins are
 * being kept. The execution of this function will not delete the file (which is
 * likely the best move) but rather will clean its content and append the
 * default code defined by another function above.
 *
 * @return boolean Whether the datastore file was resetted or not.
 */
function sucuriscan_reset_failed_logins(){
    return (bool) sucuriscan_failed_logins_datastore_path(TRUE);
}

/**
 * Generate and print the HTML code for the InfoSys page.
 *
 * This page will contains information of the system where the site is hosted,
 * also information about users in session, htaccess rules and configuration
 * options.
 *
 * @return void
 */
function sucuriscan_infosys_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri InfoSys') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PageTitle' => 'Site Info',
        'ServerInfo' => sucuriscan_server_info(),
        'Cronjobs' => sucuriscan_show_cronjobs(),
        'HTAccessIntegrity' => sucuriscan_infosys_htaccess(),
        'WordpressConfig' => sucuriscan_infosys_wpconfig(),
    );

    echo sucuriscan_get_template('infosys', $template_variables);
}

/**
 * Find the main htaccess file for the site and check whether the rules of the
 * main htaccess file of the site are the default rules generated by WordPress.
 *
 * @return string The HTML code displaying the information about the HTAccess rules.
 */
function sucuriscan_infosys_htaccess(){
    $htaccess_path = sucuriscan_get_htaccess_path();

    $template_variables = array(
        'HTAccess.Content' => '',
        'HTAccess.Message' => '',
        'HTAccess.MessageType' => '',
        'HTAccess.MessageVisible' => 'hidden',
        'HTAccess.TextareaVisible' => 'hidden',
    );

    if( $htaccess_path ){
        $htaccess_rules = file_get_contents($htaccess_path);

        $template_variables['HTAccess.MessageType'] = 'updated';
        $template_variables['HTAccess.MessageVisible'] = 'visible';
        $template_variables['HTAccess.TextareaVisible'] = 'visible';
        $template_variables['HTAccess.Content'] = $htaccess_rules;
        $template_variables['HTAccess.Message'] .= 'HTAccess file found in this path <code>'.$htaccess_path.'</code>';

        if( empty($htaccess_rules) ){
            $template_variables['HTAccess.TextareaVisible'] = 'hidden';
            $template_variables['HTAccess.Message'] .= '</p><p>The HTAccess file found is completely empty.';
        }
        if( sucuriscan_htaccess_is_standard($htaccess_rules) ){
            $template_variables['HTAccess.Message'] .= '</p><p>
                The main <code>.htaccess</code> file in your site has the standard rules for a WordPress installation. You can customize it to improve the
                performance and change the behaviour of the redirections for pages and posts in your site. To get more information visit the official documentation at
                <a href="http://codex.wordpress.org/Using_Permalinks#Creating_and_editing_.28.htaccess.29" target="_blank">Codex WordPrexx - Creating and editing (.htaccess)</a>';
        }
    }else{
        $template_variables['HTAccess.Message'] = 'Your website does not contains a <code>.htaccess</code> file or it was not found in the default location.';
        $template_variables['HTAccess.MessageType'] = 'error';
        $template_variables['HTAccess.MessageVisible'] = 'visible';
    }

    return sucuriscan_get_section('infosys-htaccess', $template_variables);
}

/**
 * Check whether the rules in a htaccess file are the default options generated
 * by WordPress or if the file has custom options added by other Plugins.
 *
 * @param  string  $rules Optional parameter containing a text string with the content of the main htaccess file.
 * @return boolean        Either TRUE or FALSE if the rules found in the htaccess file specified are the default ones or not.
 */
function sucuriscan_htaccess_is_standard($rules=FALSE){
    if( $rules===FALSE ){
        $htaccess_path = sucuriscan_get_htaccess_path();
        $rules = $htaccess_path ? file_get_contents($htaccess_path) : '';
    }

    if( !empty($rules) ){
        $standard_lines = array(
            '# BEGIN WordPress',
            '<IfModule mod_rewrite\.c>',
            'RewriteEngine On',
            'RewriteBase \/',
            'RewriteRule .index.\.php. - \[L\]',
            'RewriteCond %\{REQUEST_FILENAME\} \!-f',
            'RewriteCond %\{REQUEST_FILENAME\} \!-d',
            'RewriteRule \. \/index\.php \[L\]',
            '<\/IfModule>',
            '# END WordPress',
        );
        $pattern  = '';
        $standard_lines_total = count($standard_lines);
        foreach($standard_lines as $i=>$line){
            if( $i < ($standard_lines_total-1) ){
                $end_of_line = "\n";
            }else{
                $end_of_line = '';
            }
            $pattern .= sprintf("%s%s", $line, $end_of_line);
        }

        if( preg_match("/{$pattern}/", $rules) ){
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Retrieve all the constants and variables with their respective values defined
 * in the WordPress configuration file, only the database password constant is
 * omitted for security reasons.
 *
 * @return string The HTML code displaying the constants and variables found in the wp-config file.
 */
function sucuriscan_infosys_wpconfig(){
    $template_variables = array(
        'WordpressConfig.Rules' => '',
        'WordpressConfig.Total' => 0,
        'WordpressConfig.Content' => '',
        'WordpressConfig.ThickboxURL' => '#TB_inline?',
    );
    $ignore_wp_rules = array('DB_PASSWORD');
    $template_variables['WordpressConfig.ThickboxURL'] .= http_build_query(array(
        'width' => '800',
        'height' => '550',
        'inlineId' => 'sucuriscan-wpconfig-content',
    ));

    $wp_config_path = sucuriscan_get_wpconfig_path();
    if( $wp_config_path ){
        add_thickbox();
        $wp_config_content = file($wp_config_path);
        $template_variables['WordpressConfig.Content'] = file_get_contents($wp_config_path);

        // Read WordPress main configuration file as text plain.
        $wp_config_rules = array();
        foreach( (array)$wp_config_content as $line ){
            $line = str_replace("\n", '', $line);

            // Ignore useless lines and append to the clean string the important lines.
            if( preg_match('/^define\(/', $line) ){
                $line = str_replace('define(', '', $line);
                $line = preg_replace('/\);.*/', '', $line);
                $line_parts = explode(',', $line, 2);
            }
            else if( preg_match('/^\$[a-zA-Z_]+/', $line) ){
                $line_parts = explode('=', $line, 2);
            }
            else{ continue; }

            // Clean and append the rule to the wp_config_rules variable.
            if( isset($line_parts) && count($line_parts)==2 ){
                $key_name = $key_value = '';
                foreach($line_parts as $i=>$line_part){
                    $line_part = trim($line_part);
                    $line_part = ltrim($line_part, '$');
                    $line_part = rtrim($line_part, ';');

                    // Remove single/double quotes at the beginning and end of the string.
                    $line_part = ltrim($line_part, "'");
                    $line_part = rtrim($line_part, "'");
                    $line_part = ltrim($line_part, '"');
                    $line_part = rtrim($line_part, '"');

                    // Assign the clean strings to specific variables.
                    if( $i==0 ){ $key_name  = $line_part; }
                    if( $i==1 ){ $key_value = $line_part; }
                }

                if( !in_array($key_name, $ignore_wp_rules) ){
                    $wp_config_rules[$key_name] = $key_value;
                }
            }
        }

        // Pass the WordPress configuration rules to the template and show them.
        $counter = 0;
        foreach( $wp_config_rules as $var_name=>$var_value ){
            $counter += 1;
            $template_variables['WordpressConfig.Total'] += 1;
            $template_variables['WordpressConfig.Rules'] .= sucuriscan_get_snippet('infosys-wpconfig', array(
                'WordpressConfig.VariableName' => $var_name,
                'WordpressConfig.VariableValue' => htmlentities($var_value),
                'WordpressConfig.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
            ));
        }
    }

    return sucuriscan_get_section('infosys-wpconfig', $template_variables);
}

/**
 * Retrieve a list with the scheduled tasks configured for the site.
 *
 * @return array A list of pseudo-variables and values that will replace them in the HTML template.
 */
function sucuriscan_show_cronjobs(){
    $template_variables = array(
        'Cronjobs.List' => '',
        'Cronjobs.Total' => 0,
    );

    $cronjobs = _get_cron_array();
    $schedules = wp_get_schedules();
    $date_format = _x('M j, Y - H:i', 'Publish box date format', 'cron-view' );
    $counter = 0;

    foreach( $cronjobs as $timestamp=>$cronhooks ){
        foreach( (array)$cronhooks as $hook=>$events ){
            foreach( (array)$events as $key=>$event ){
                $counter += 1;
                $cronjob_snippet = '';
                $template_variables['Cronjobs.Total'] += 1;
                $template_variables['Cronjobs.List'] .= sucuriscan_get_snippet('infosys-cronjobs', array(
                    'Cronjob.Task' => ucwords(str_replace('_',chr(32),$hook)),
                    'Cronjob.Schedule' => $event['schedule'],
                    'Cronjob.Nexttime' => date_i18n($date_format, $timestamp),
                    'Cronjob.Hook' => $hook,
                    'Cronjob.Arguments' => implode(', ', $event['args']),
                    'Cronjob.CssClass' => ( $counter%2 == 0 ) ? '' : 'alternate'
                ));
            }
        }
    }

    return sucuriscan_get_section('infosys-cronjobs', $template_variables);
}

/**
 * Gather information from the server, database engine, and PHP interpreter.
 *
 * @return array A list of pseudo-variables and values that will replace them in the HTML template.
 */
function sucuriscan_server_info(){
    global $wpdb;

    if( current_user_can('manage_options') ){
        $memory_usage = function_exists('memory_get_usage') ? round(memory_get_usage()/1024/1024,2).' MB' : 'N/A';
        $mysql_version = $wpdb->get_var('SELECT VERSION() AS version');
        $mysql_info = $wpdb->get_results('SHOW VARIABLES LIKE "sql_mode"');
        $sql_mode = ( is_array($mysql_info) && !empty($mysql_info[0]->Value) ) ? $mysql_info[0]->Value : 'Not set';
        $runtime_scan = sucuriscan_get_option('sucuriscan_runtime');
        $runtime_scan_human = date( 'd/M/Y H:i:s', $runtime_scan );

        $template_variables = array(
            'PluginVersion' => SUCURISCAN_VERSION,
            'PluginMD5' => SUCURISCAN_PLUGIN_CHECKSUM,
            'PluginRuntimeDatetime' => $runtime_scan_human,
            'OperatingSystem' => sprintf('%s (%d Bit)', PHP_OS, PHP_INT_SIZE*8),
            'Server' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'MemoryUsage' => $memory_usage,
            'MySQLVersion' => $mysql_version,
            'SQLMode' => $sql_mode,
            'PHPVersion' => PHP_VERSION,
        );

        $field_names = array(
            'safe_mode',
            'allow_url_fopen',
            'memory_limit',
            'upload_max_filesize',
            'post_max_size',
            'max_execution_time',
            'max_input_time',
        );

        foreach( $field_names as $php_flag ){
            $php_flag_name = ucwords(str_replace('_', chr(32), $php_flag) );
            $tpl_varname = str_replace(chr(32), '', $php_flag_name);
            $php_flag_value = ini_get($php_flag);
            $template_variables[$tpl_varname] = $php_flag_value ? $php_flag_value : 'N/A';
        }
    }

    return sucuriscan_get_section('infosys-serverinfo', $template_variables);
}

/**
 * Global variables used by the functions bellow.
 *
 * These are lists of options allowed to use in the execution of the monitoring
 * tool, and the administrator can select among them in the settings page.
 *
 * @var array
 */
$sucuriscan_notify_options = array(
    'sucuriscan_notify_user_registration' => 'Enable email alerts for new user registration',
    'sucuriscan_notify_success_login' => 'Enable email alerts for successful logins',
    'sucuriscan_notify_failed_login' => 'Enable email alerts for failed logins',
    'sucuriscan_notify_bruteforce_attack' => 'Enable email alerts for login brute-force attack',
    'sucuriscan_notify_post_publication' => 'Enable email alerts for new site content',
    'sucuriscan_notify_theme_editor' => 'Enable email alerts when a file is modified via the theme/plugin editor',
    'sucuriscan_notify_website_updated' => 'Enable email alerts when your website is updated',
    'sucuriscan_notify_settings_updated' => 'Enable email alerts when your website settings are updated',
    'sucuriscan_notify_theme_switched' => 'Enable email alerts when the website theme is switched',
    'sucuriscan_notify_theme_updated' => 'Enable email alerts when a theme is updated',
    'sucuriscan_notify_widget_added' => 'Enable email alerts when a widget is added to a sidebar',
    'sucuriscan_notify_widget_deleted' => 'Enable email alerts when a widget is deleted from a sidebar',
    'sucuriscan_notify_plugin_change' => 'Enable email alerts for Sucuri plugin changes',
    'sucuriscan_notify_plugin_activated' => 'Enable email alerts when a plugin is activated',
    'sucuriscan_notify_plugin_deactivated' => 'Enable email alerts when a plugin is deactivated',
    'sucuriscan_notify_plugin_updated' => 'Enable email alerts when a plugin is updated',
    'sucuriscan_notify_plugin_installed' => 'Enable email alerts when a plugin is installed',
    'sucuriscan_notify_plugin_deleted' => 'Enable email alerts when a plugin is deleted',
    'sucuriscan_prettify_mails' => 'Enable email alerts in HTML (uncheck to get email in text/plain)',
    'sucuriscan_lastlogin_redirection' => 'Allow redirection after login to report the last-login information',
);

$sucuriscan_schedule_allowed = array(
    'hourly' => 'Every three hours (3 hours)',
    'twicedaily' => 'Twice daily (12 hours)',
    'daily' => 'Once daily (24 hours)',
    '_oneoff' => 'Never',
);

$sucuriscan_interface_allowed = array(
    'spl' => 'SPL (high performance)',
    'opendir' => 'OpenDir (medium)',
    'glob' => 'Glob (low)',
);

$sucuriscan_emails_per_hour = array(
    '5' => 'Maximum 5 per hour',
    '10' => 'Maximum 10 per hour',
    '20' => 'Maximum 20 per hour',
    '40' => 'Maximum 40 per hour',
    '80' => 'Maximum 80 per hour',
    '160' => 'Maximum 160 per hour',
    'unlimited' => 'Unlimited',
);

$sucuriscan_maximum_failed_logins = array(
    '30' => '30 failed logins per hour',
    '60' => '60 failed logins per hour',
    '120' => '120 failed logins per hour',
    '240' => '240 failed logins per hour',
    '480' => '480 failed logins per hour',
);

$sucuriscan_verify_ssl_cert = array(
    'true' => 'Verify peer\'s cert',
    'false' => 'Stop peer\'s cert verification',
);

/**
 * Print a HTML code with the settings of the plugin.
 *
 * @return void
 */
function sucuriscan_settings_page(){
    $template_variables = array(
        'PageTitle' => 'Settings',
        'Settings.General' => sucuriscan_settings_general(),
        'Settings.Notifications' => sucuriscan_settings_notifications(),
        'Settings.IgnoreRules' => sucuriscan_settings_ignore_rules(),
    );

    echo sucuriscan_get_template('settings', $template_variables);
}

/**
 * Process the requests sent by the form submissions originated in the settings
 * page, all forms must have a nonce field that will be checked against the one
 * generated in the template render function.
 *
 * @param  boolean $page_nonce True if the nonce is valid, False otherwise.
 * @return void
 */
function sucuriscan_settings_form_submissions( $page_nonce=NULL ){

    global $sucuriscan_schedule_allowed,
        $sucuriscan_interface_allowed,
        $sucuriscan_notify_options,
        $sucuriscan_emails_per_hour,
        $sucuriscan_maximum_failed_logins,
        $sucuriscan_verify_ssl_cert;

    // Use this conditional to avoid double checking.
    if( is_null($page_nonce) ){
        $page_nonce = sucuriscan_check_page_nonce();
    }

    if( $page_nonce ){

        // Recover API key through the email registered previously.
        if( isset($_POST['sucuriscan_recover_api_key']) ){
            sucuriscan_recover_api_key();
        }

        // Save API key after it was recovered by the administrator.
        if( isset($_POST['sucuriscan_manual_api_key']) ){
            sucuriscan_set_api_key( $_POST['sucuriscan_manual_api_key'], TRUE );
            sucuriscan_create_scheduled_task();
        }

        // Remove API key from the local storage.
        if( isset($_POST['sucuriscan_remove_api_key']) ){
            sucuriscan_set_api_key('');
            wp_clear_scheduled_hook('sucuriscan_scheduled_scan');
            sucuriscan_notify_event( 'plugin_change', 'Sucuri API key removed' );
        }

        // Modify the schedule of the filesystem scanner.
        if(
            isset($_POST['sucuriscan_scan_frequency'])
            && isset($sucuriscan_schedule_allowed)
        ){
            $frequency = $_POST['sucuriscan_scan_frequency'];
            $current_frequency = sucuriscan_get_option('sucuriscan_scan_frequency');
            $allowed_frequency = array_keys($sucuriscan_schedule_allowed);

            if( in_array($frequency, $allowed_frequency) && $current_frequency != $frequency ){
                update_option('sucuriscan_scan_frequency', $frequency);
                wp_clear_scheduled_hook('sucuriscan_scheduled_scan');

                if( $frequency != '_oneoff' ){
                    wp_schedule_event( time()+10, $frequency, 'sucuriscan_scheduled_scan' );
                }

                sucuriscan_notify_event( 'plugin_change', 'Filesystem scanning frequency changed to: ' . $frequency );
                sucuriscan_info( 'Filesystem scan scheduled to run <code>'.$frequency.'</code>' );
            }
        }

        // Set the method (aka. interface) that will be used to scan the site.
        if(
            isset($_POST['sucuriscan_scan_interface'])
            && isset($sucuriscan_interface_allowed)
        ){
            $interface = trim($_POST['sucuriscan_scan_interface']);
            $allowed_values = array_keys($sucuriscan_interface_allowed);

            if( in_array($interface, $allowed_values) ){
                update_option('sucuriscan_scan_interface', $interface);
                sucuriscan_notify_event( 'plugin_change', 'Filesystem scanning interface changed to: ' . $interface );
                sucuriscan_info( 'Filesystem scan interface set to <code>'.$interface.'</code>' );
            }
        }

        // Update the value for the maximum emails per hour.
        if( isset($_POST['sucuriscan_emails_per_hour']) ){
            $per_hour = esc_attr($_POST['sucuriscan_emails_per_hour']);

            if( array_key_exists($per_hour, $sucuriscan_emails_per_hour) ){
                $per_hour_label = $sucuriscan_emails_per_hour[$per_hour];
                update_option( 'sucuriscan_emails_per_hour', $per_hour );
                sucuriscan_notify_event( 'plugin_change', 'Maximum email notifications per hour changed' );
                sucuriscan_info( 'E-mail notifications: <code>' . $per_hour_label . '</code>' );
            } else {
                sucuriscan_error( 'Invalid value for the maximum emails per hour.' );
            }
        }

        // Update the email where the event notifications will be sent.
        if( isset($_POST['sucuriscan_notify_to']) ){
            $new_email = esc_attr($_POST['sucuriscan_notify_to']);

            if( is_valid_email($new_email) ){
                update_option( 'sucuriscan_notify_to', $new_email );
                sucuriscan_notify_event( 'plugin_change', 'Email address to get the event notifications was changed' );
                sucuriscan_info( 'All the event notifications will be sent to the email specified.' );
            } else {
                sucuriscan_error( 'Email format not supported.' );
            }
        }

        // Update the maximum failed logins per hour before consider it a brute-force attack.
        if( isset($_POST['sucuriscan_maximum_failed_logins']) ){
            $failed_logins = esc_attr($_POST['sucuriscan_maximum_failed_logins']);

            if( array_key_exists($failed_logins, $sucuriscan_maximum_failed_logins) ){
                update_option( 'sucuriscan_maximum_failed_logins', $failed_logins );
                sucuriscan_notify_event( 'plugin_change', 'Maximum failed logins before consider it a brute-force attack was changed' );
                sucuriscan_info(
                    'A brute-force attack event will be reported if there are more than '
                    . '<code>' . $failed_logins . '</code> failed logins per hour.'
                );
            } else {
                sucuriscan_error( 'Invalid value for the maximum failed logins per hour before consider it a brute-force attack.' );
            }
        }

        // Update the configuration for the SSL certificate verification.
        if( isset($_POST['sucuriscan_verify_ssl_cert']) ){
            $verify_ssl_cert = esc_attr($_POST['sucuriscan_verify_ssl_cert']);

            if( array_key_exists($verify_ssl_cert, $sucuriscan_verify_ssl_cert) ){
                update_option( 'sucuriscan_verify_ssl_cert', $verify_ssl_cert );
                $message = 'SSL certificates will not be verified when executing a HTTP request '
                    . 'while communicating with the Sucuri API service, nor the official '
                    . 'WordPress API.';
                sucuriscan_notify_event( 'plugin_change', $message );
                sucuriscan_info( $message );
            } else {
                sucuriscan_error( 'Invalid value for the SSL certificate verification.' );
            }
        }

        // Update the notification settings.
        if(
            isset($_POST['sucuriscan_save_notification_settings'])
            && isset($sucuriscan_notify_options)
        ){
            $options_updated_counter = 0;

            foreach( $sucuriscan_notify_options as $alert_type => $alert_label ){
                if( isset($_POST[$alert_type]) ){
                    $option_value = ( $_POST[$alert_type] == 1 ? 'enabled' : 'disabled' );
                    update_option( $alert_type, $option_value );
                    $options_updated_counter += 1;
                }
            }

            if( $options_updated_counter > 0 ){
                sucuriscan_notify_event( 'plugin_change', 'Email notification settings changed' );
                sucuriscan_info( 'Notification settings updated.' );
            }
        }

        // Reset all the plugin's options.
        if( isset($_POST['sucuriscan_reset_options']) ){
            // Notify the event before the API key is removed.
            $event_msg = 'All plugins options were resetted';
            sucuriscan_report_event( 1, 'core', $event_msg );
            sucuriscan_notify_event( 'plugin_change', $event_msg );

            // Remove all plugin's options from the database.
            $options = sucuriscan_get_options_from_db('all_sucuriscan_options');

            foreach( $options as $option ){
                delete_option( $option->option_name );
            }

            // Remove the scheduled tasks.
            wp_clear_scheduled_hook('sucuriscan_scheduled_scan');

            sucuriscan_info( 'All plugin options were resetted successfully' );
        }

        // Ignore a new event for email notifications.
        if(
            isset($_POST['sucuriscan_ignorerule_action'])
            && isset($_POST['sucuriscan_ignorerule'])
        ){
            if( $_POST['sucuriscan_ignorerule_action'] == 'add' ){
                $event_ignored = sucuriscan_add_ignored_event( $_POST['sucuriscan_ignorerule'] );

                if( $event_ignored ){
                    sucuriscan_info( 'Post-type ignored successfully.' );
                } else {
                    sucuriscan_error( 'The post-type is invalid or it may be already ignored.' );
                }
            } else {
                sucuriscan_remove_ignored_event( $_POST['sucuriscan_ignorerule'] );
                sucuriscan_info( 'Post-type removed from the list successfully.' );
            }
        }

    }

}

/**
 * Read and parse the content of the general settings template.
 *
 * @return string Parsed HTML code for the general settings panel.
 */
function sucuriscan_settings_general(){

    global $sucuriscan_schedule_allowed,
        $sucuriscan_interface_allowed,
        $sucuriscan_emails_per_hour,
        $sucuriscan_maximum_failed_logins,
        $sucuriscan_verify_ssl_cert;

    // Check the nonce here to populate the value through other functions.
    $page_nonce = sucuriscan_check_page_nonce();

    // Process all form submissions.
    sucuriscan_settings_form_submissions($page_nonce);

    // Register the site, get its API key, and store it locally for future usage.
    $api_registered_modal = '';

    // Whether the form to manually add the API key should be shown or not.
    $display_manual_key_form = (bool) isset($_POST['sucuriscan_recover_api_key']);

    if( $page_nonce && isset($_POST['sucuriscan_wordpress_apikey']) ){
        $registered = sucuriscan_register_site();

        if( $registered ){
            $api_registered_modal = sucuriscan_get_modal('settings-apiregistered', array(
                'Title' => 'Site registered successfully',
                'CssClass' => 'sucuriscan-apikey-registered',
            ));
        } else {
            $display_manual_key_form = TRUE;
        }
    }

    // Get initial variables to decide some things bellow.
    $api_key = sucuriscan_wordpress_apikey();
    $scan_freq = sucuriscan_get_option('sucuriscan_scan_frequency');
    $scan_interface = sucuriscan_get_option('sucuriscan_scan_interface');
    $emails_per_hour = sucuriscan_get_option('sucuriscan_emails_per_hour');
    $maximum_failed_logins = sucuriscan_get_option('sucuriscan_maximum_failed_logins');
    $verify_ssl_cert = sucuriscan_get_option('sucuriscan_verify_ssl_cert');
    $runtime_scan = sucuriscan_get_option('sucuriscan_runtime');
    $runtime_scan_human = date( 'd/M/Y H:i:s', $runtime_scan );

    // Generate HTML code to configure the scanning frequency from the plugin settings.
    $scan_freq_options = '';
    foreach( $sucuriscan_schedule_allowed as $schedule => $schedule_label ){
        $selected = ( $scan_freq==$schedule ? 'selected="selected"' : '' );
        $scan_freq_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $schedule, $selected, $schedule_label
        );
    }

    // Generate HTML code to configure the scanning interface from the plugin settings.
    $scan_interface_options = '';
    foreach( $sucuriscan_interface_allowed as $interface_name => $interface_desc ){
        $selected = ( $scan_interface == $interface_name ? 'selected="selected"' : '' );
        $scan_interface_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $interface_name,
            $selected,
            $interface_desc
        );
    }

    // Generate the HTML code to configure the emails per hour.
    $emails_per_hour_options = '';
    foreach( $sucuriscan_emails_per_hour as $per_hour => $per_hour_label ){
        $selected = ( $emails_per_hour == $per_hour ? 'selected="selected"' : '' );
        $emails_per_hour_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $per_hour,
            $selected,
            $per_hour_label
        );
    }

    // Generate the HTML code to configure the emails per hour.
    $maximum_failed_logins_options = '';
    foreach( $sucuriscan_maximum_failed_logins as $per_hour => $per_hour_label ){
        $selected = ( $maximum_failed_logins == $per_hour ? 'selected="selected"' : '' );
        $maximum_failed_logins_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $per_hour,
            $selected,
            $per_hour_label
        );
    }

    // Generate the HTML code to configure the emails per hour.
    $verify_ssl_cert_options = '';
    foreach( $sucuriscan_verify_ssl_cert as $verify => $verify_label ){
        $selected = ( $verify_ssl_cert == $verify ? 'selected="selected"' : '' );
        $verify_ssl_cert_options .= sprintf(
            '<option value="%s" %s>%s</option>',
            $verify,
            $selected,
            $verify_label
        );
    }

    $template_variables = array(
        'APIKey' => $api_key,
        'APIKey.RecoverVisibility' => ( $api_key || $display_manual_key_form ? 'hidden' : 'visible' ),
        'APIKey.ManualKeyFormVisibility' => ( $display_manual_key_form ? 'visible' : 'hidden' ),
        'APIKey.RemoveVisibility' => ( $api_key ? 'visible' : 'hidden' ),
        'ScanningFrequency' => 'Undefined',
        'ScanningFrequencyOptions' => $scan_freq_options,
        'ScanningInterface' => ( $scan_interface ? $sucuriscan_interface_allowed[$scan_interface] : 'Undefined' ),
        'ScanningInterfaceOptions' => $scan_interface_options,
        'ScanningInterfaceVisibility' => ( SucuriScanFileInfo::is_spl_available() ? 'hidden' : 'visible' ),
        'ScanningRuntime' => $runtime_scan,
        'ScanningRuntimeHuman' => $runtime_scan_human,
        'ModalWhenAPIRegistered' => $api_registered_modal,
        'NotifyTo' => sucuriscan_get_option('sucuriscan_notify_to'),
        'EmailsPerHour' => 'Undefined',
        'EmailsPerHourOptions' => $emails_per_hour_options,
        'MaximumFailedLogins' => 'Undefined',
        'MaximumFailedLoginsOptions' => $maximum_failed_logins_options,
        'VerifySSLCert' => 'Undefined',
        'VerifySSLCertOptions' => $verify_ssl_cert_options,
        'ModalWhenAPIRegistered' => $api_registered_modal,
    );

    if( array_key_exists($scan_freq, $sucuriscan_schedule_allowed) ){
        $template_variables['ScanningFrequency'] = $sucuriscan_schedule_allowed[$scan_freq];
    }

    if( array_key_exists($emails_per_hour, $sucuriscan_emails_per_hour) ){
        $template_variables['EmailsPerHour'] = $sucuriscan_emails_per_hour[$emails_per_hour];
    }

    if( array_key_exists($maximum_failed_logins, $sucuriscan_maximum_failed_logins) ){
        $template_variables['MaximumFailedLogins'] = $sucuriscan_maximum_failed_logins[$maximum_failed_logins];
    }

    if( array_key_exists($verify_ssl_cert, $sucuriscan_verify_ssl_cert) ){
        $template_variables['VerifySSLCert'] = $sucuriscan_verify_ssl_cert[$verify_ssl_cert];
    }

    return sucuriscan_get_section('settings-general', $template_variables);
}

/**
 * Read and parse the content of the notification settings template.
 *
 * @return string Parsed HTML code for the notification settings panel.
 */
function sucuriscan_settings_notifications(){
    global $sucuriscan_notify_options;

    $template_variables = array(
        'NotificationOptions' => '',
    );

    $counter = 0;

    foreach( $sucuriscan_notify_options as $alert_type => $alert_label ){
        $alert_value = sucuriscan_get_option($alert_type);
        $checked = ( $alert_value == 'enabled' ? 'checked="checked"' : '' );
        $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';

        $template_variables['NotificationOptions'] .= sucuriscan_get_snippet('settings-notifications', array(
            'Notification.CssClass' => $css_class,
            'Notification.Name' => $alert_type,
            'Notification.Checked' => $checked,
            'Notification.Label' => $alert_label,
        ));
        $counter += 1;
    }

    return sucuriscan_get_section('settings-notifications', $template_variables);
}

/**
 * Read and parse the content of the ignored-rules settings template.
 *
 * @return string Parsed HTML code for the ignored-rules settings panel.
 */
function sucuriscan_settings_ignore_rules(){
    $notify_new_site_content = sucuriscan_get_option('sucuriscan_notify_post_publication');

    $template_variables = array(
        'IgnoreRules.MessageVisibility' => 'visible',
        'IgnoreRules.TableVisibility' => 'hidden',
        'IgnoreRules.PostTypes' => '',
    );

    if( $notify_new_site_content == 'enabled' ){
        $post_types = get_post_types();
        $ignored_events = sucuriscan_get_ignored_events();

        $template_variables['IgnoreRules.MessageVisibility'] = 'hidden';
        $template_variables['IgnoreRules.TableVisibility'] = 'visible';
        $counter = 0;

        foreach( $post_types as $post_type => $post_type_object ){
            $counter += 1;
            $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';
            $post_type_title = ucwords( str_replace('_', chr(32), $post_type) );

            if( array_key_exists($post_type, $ignored_events) ){
                $is_ignored_text = 'YES';
                $was_ignored_at = @date('d/M/Y - H:i:s', $ignored_events[$post_type]);
                $is_ignored_class = 'danger';
                $button_action = 'remove';
                $button_class = 'button-primary';
                $button_text = 'Allow';
            } else {
                $is_ignored_text = 'NO';
                $button_action = 'add';
                $was_ignored_at = 'Not ignored';
                $is_ignored_class = 'success';
                $button_class = 'button-primary button-danger';
                $button_text = 'Ignore';
            }

            $template_variables['IgnoreRules.PostTypes'] .= sucuriscan_get_snippet('settings-ignorerules', array(
                'IgnoreRules.CssClass' => $css_class,
                'IgnoreRules.Num' => $counter,
                'IgnoreRules.PostTypeTitle' => $post_type_title,
                'IgnoreRules.IsIgnored' => $is_ignored_text,
                'IgnoreRules.WasIgnoredAt' => $was_ignored_at,
                'IgnoreRules.IsIgnoredClass' => $is_ignored_class,
                'IgnoreRules.PostType' => $post_type,
                'IgnoreRules.Action' => $button_action,
                'IgnoreRules.ButtonClass' => 'button ' . $button_class,
                'IgnoreRules.ButtonText' => $button_text,
            ));
        }
    }

    return sucuriscan_get_section('settings-ignorerules', $template_variables);
}

