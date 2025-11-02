<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Configuration
define('UPLOAD_DIR', 'uploads');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_EXTENSIONS', ['html', 'htm']);
define('ALLOWED_MIME_TYPES', ['text/html', 'text/plain', 'application/octet-stream']);

// Get base URL
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$base_url = $protocol . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/';
$script_name = basename($_SERVER['SCRIPT_NAME']);

// Initialize upload directory with security
if (!file_exists(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
    file_put_contents(UPLOAD_DIR . '/.htaccess', "Options -Indexes\nDeny from all\n");
    file_put_contents(UPLOAD_DIR . '/index.php', '<?php http_response_code(403); exit; ?>');
}

// Security headers
header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Core Functions
function generateUniqueId($length = 16) {
    return bin2hex(random_bytes($length / 2));
}

function validateMimeType($filepath) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filepath);
    finfo_close($finfo);
    return in_array($mime, ALLOWED_MIME_TYPES);
}

function isValidHTML($content) {
    // Remove null bytes
    $content = str_replace("\0", '', $content);
    $content = trim($content);
    
    if (empty($content) || strlen($content) < 10) {
        return false;
    }
    
    // Must contain HTML tags
    if (!preg_match('/<[^>]+>/', $content)) {
        return false;
    }
    
    // Block dangerous patterns
    $dangerousPatterns = [
        '/<\?(php|=)/i',                    // PHP tags
        '/<%(.*?)%>/i',                     // ASP tags
        '/<script[^>]*src=[^>]*\.php/i',   // PHP in script src
        '/on\w+\s*=\s*["\'].*?php/i',      // PHP in event handlers
    ];
    
    foreach ($dangerousPatterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return false;
        }
    }
    
    return true;
}

function sanitizeFilename($filename) {
    $filename = pathinfo($filename, PATHINFO_FILENAME);
    $filename = preg_replace('/[^a-zA-Z0-9_-]/', '', $filename);
    return substr($filename ?: 'file', 0, 50);
}

function formatFileSize($bytes) {
    if ($bytes === 0) return '0 Bytes';
    $k = 1024;
    $sizes = ['Bytes', 'KB', 'MB'];
    $i = floor(log($bytes) / log($k));
    return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
}

// Handle file upload
$upload_success = false;
$upload_error = null;
$upload_data = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    // Validation chain
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $upload_error = ['title' => 'Upload Error', 'message' => 'There was an error uploading your file. Please try again.'];
    } elseif ($file['size'] > MAX_FILE_SIZE) {
        $upload_error = ['title' => 'File Too Large', 'message' => 'File size must be less than ' . formatFileSize(MAX_FILE_SIZE) . '.'];
    } elseif ($file['size'] === 0) {
        $upload_error = ['title' => 'Empty File', 'message' => 'The uploaded file is empty.'];
    } else {
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!in_array($extension, ALLOWED_EXTENSIONS)) {
            $upload_error = ['title' => 'Invalid File Type', 'message' => 'Only HTML files (.html, .htm) are allowed.'];
        } elseif (!validateMimeType($file['tmp_name'])) {
            $upload_error = ['title' => 'Invalid File', 'message' => 'The file does not appear to be a valid HTML file.'];
        } else {
            $content = file_get_contents($file['tmp_name']);
            
            if (!isValidHTML($content)) {
                $upload_error = ['title' => 'Invalid HTML', 'message' => 'The file contains invalid HTML or potentially dangerous content.'];
            } else {
                $uniqueId = generateUniqueId();
                $safeFilename = sanitizeFilename($file['name']);
                $filename = $uniqueId . '_' . $safeFilename . '.html';
                $filepath = UPLOAD_DIR . '/' . $filename;
                
                if (move_uploaded_file($file['tmp_name'], $filepath)) {
                    chmod($filepath, 0644);
                    
                    $upload_data = [
                        'id' => $uniqueId,
                        'filename' => $filename,
                        'original_name' => $file['name'],
                        'size' => $file['size'],
                        'url' => $base_url . $script_name . '?x=' . $uniqueId,
                        'timestamp' => time()
                    ];
                    
                    $upload_success = true;
                } else {
                    $upload_error = ['title' => 'Storage Error', 'message' => 'Failed to save the file. Please check permissions and try again.'];
                }
            }
        }
    }
}

// Handle file viewing
if (isset($_GET['x'])) {
    $fileId = preg_replace('/[^a-f0-9]/', '', $_GET['x']);
    
    if (strlen($fileId) !== 16) {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><title>404 - Not Found</title></head><body><h1>File Not Found</h1></body></html>';
        exit;
    }
    
    $files = glob(UPLOAD_DIR . '/' . $fileId . '_*.html');
    
    if (!empty($files) && file_exists($files[0])) {
        // Handle file deletion
        if (isset($_GET['delete']) && isset($_GET['confirm'])) {
            if (unlink($files[0])) {
                header('Location: ' . $base_url . $script_name . '?deleted=1');
                exit;
            } else {
                http_response_code(500);
                echo '<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Failed to delete file</h1></body></html>';
                exit;
            }
        }
        
        // Serve the HTML file with security headers
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        
        // Balanced CSP: Allow external resources but restrict inline execution where possible
        header("Content-Security-Policy: default-src 'self' https: http:; script-src 'self' https: http: 'unsafe-inline' 'unsafe-eval'; style-src 'self' https: http: 'unsafe-inline'; img-src 'self' https: http: data: blob:; font-src 'self' https: http: data:; connect-src 'self' https: http:;");
        
        readfile($files[0]);
        exit;
    } else {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><title>404 - Not Found</title></head><body><h1>File Not Found</h1><p>The requested file does not exist or has been deleted.</p></body></html>';
        exit;
    }
}

// Get upload statistics
$upload_count = 0;
$total_size = 0;
if (is_dir(UPLOAD_DIR)) {
    $files = glob(UPLOAD_DIR . '/*.html');
    $upload_count = count($files);
    foreach ($files as $file) {
        $total_size += filesize($file);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>xsukax - Free HTML File Hosting</title>
    <meta name="description" content="Free HTML file hosting service with full CSS and JavaScript support. Upload and share your HTML pages instantly.">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-50 min-h-screen">
    <!-- Header -->
    <header class="bg-white border-b border-gray-200">
        <div class="container mx-auto px-4 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 bg-gray-900 rounded-lg flex items-center justify-center">
                        <i class="fas fa-code text-white"></i>
                    </div>
                    <div>
                        <h1 class="text-xl font-bold text-gray-900">xsukax</h1>
                        <p class="text-xs text-gray-600">Free HTML File Hosting</p>
                    </div>
                </div>
                <div class="flex items-center space-x-4 text-xs text-gray-600">
                    <span class="hidden sm:inline"><i class="fas fa-file-code text-blue-500 mr-1"></i><?php echo number_format($upload_count); ?> files</span>
                    <span class="hidden sm:inline"><i class="fas fa-database text-green-500 mr-1"></i><?php echo formatFileSize($total_size); ?></span>
                    <span class="bg-green-100 text-green-700 px-2 py-1 rounded font-medium"><i class="fas fa-check-circle mr-1"></i>Public</span>
                </div>
            </div>
        </div>
    </header>

    <main class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- Success Message -->
        <?php if ($upload_success && $upload_data): ?>
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6 animate-fade-in">
            <div class="flex items-start mb-4">
                <div class="w-12 h-12 bg-green-50 rounded-lg flex items-center justify-center mr-4 flex-shrink-0">
                    <i class="fas fa-check-circle text-green-500 text-2xl"></i>
                </div>
                <div class="flex-1">
                    <h2 class="text-xl font-bold text-gray-900 mb-1">Upload Successful!</h2>
                    <p class="text-gray-600 text-sm">Your HTML file is ready to share with the world</p>
                </div>
            </div>
            
            <div class="bg-gray-50 rounded-lg p-4 mb-4 border border-gray-200">
                <label class="block text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">
                    <i class="fas fa-link mr-1"></i>Shareable URL
                </label>
                <div class="flex items-center gap-2">
                    <input type="text" readonly value="<?php echo htmlspecialchars($upload_data['url']); ?>" 
                           class="flex-1 px-3 py-2 bg-white border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-gray-900 select-all"
                           id="shareUrl">
                    <button onclick="copyUrl()" 
                            class="bg-gray-900 text-white px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors text-sm font-medium whitespace-nowrap">
                        <i class="fas fa-copy mr-1"></i>Copy
                    </button>
                </div>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div class="bg-white border border-gray-200 rounded-lg p-3">
                    <div class="text-xs text-gray-600 mb-1">Filename</div>
                    <div class="font-semibold text-sm text-gray-900 truncate" title="<?php echo htmlspecialchars($upload_data['original_name']); ?>">
                        <i class="fas fa-file-code text-blue-500 mr-1"></i>
                        <?php echo htmlspecialchars($upload_data['original_name']); ?>
                    </div>
                </div>
                <div class="bg-white border border-gray-200 rounded-lg p-3">
                    <div class="text-xs text-gray-600 mb-1">File Size</div>
                    <div class="font-semibold text-sm text-gray-900">
                        <i class="fas fa-weight text-green-500 mr-1"></i>
                        <?php echo formatFileSize($upload_data['size']); ?>
                    </div>
                </div>
                <div class="bg-white border border-gray-200 rounded-lg p-3">
                    <div class="text-xs text-gray-600 mb-1">File ID</div>
                    <div class="font-semibold text-sm text-gray-900 font-mono">
                        <i class="fas fa-fingerprint text-purple-500 mr-1"></i>
                        <?php echo substr($upload_data['id'], 0, 8); ?>...
                    </div>
                </div>
            </div>
            
            <div class="flex gap-3">
                <a href="<?php echo htmlspecialchars($upload_data['url']); ?>" target="_blank" 
                   class="flex-1 bg-blue-500 text-white px-4 py-2.5 rounded-lg hover:bg-blue-600 transition-colors text-center text-sm font-medium">
                    <i class="fas fa-external-link-alt mr-2"></i>View File
                </a>
                <button onclick="confirmDelete('<?php echo htmlspecialchars($upload_data['url']); ?>')" 
                   class="flex-1 bg-red-500 text-white px-4 py-2.5 rounded-lg hover:bg-red-600 transition-colors text-center text-sm font-medium">
                    <i class="fas fa-trash-alt mr-2"></i>Delete File
                </button>
            </div>
        </div>
        <?php endif; ?>

        <!-- Delete Success Message -->
        <?php if (isset($_GET['deleted'])): ?>
        <div class="bg-green-50 border border-green-200 rounded-lg p-4 mb-6 animate-fade-in">
            <div class="flex items-center">
                <i class="fas fa-check-circle text-green-500 mr-3"></i>
                <span class="text-green-700 text-sm font-medium">File deleted successfully</span>
            </div>
        </div>
        <?php endif; ?>

        <!-- Welcome Banner -->
        <?php if (!$upload_success && !isset($_GET['deleted'])): ?>
        <div class="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg shadow-lg p-6 mb-6 text-white">
            <div class="flex items-center justify-between flex-wrap gap-4">
                <div class="flex-1 min-w-0">
                    <h2 class="text-2xl font-bold mb-2">Welcome to xsukax</h2>
                    <p class="text-blue-100 text-sm">Upload your HTML files instantly. No registration required. 100% free.</p>
                </div>
                <div class="flex items-center space-x-3 text-sm">
                    <div class="text-center">
                        <div class="text-2xl font-bold"><?php echo number_format($upload_count); ?></div>
                        <div class="text-blue-100 text-xs">Files Hosted</div>
                    </div>
                    <div class="w-px h-12 bg-blue-400"></div>
                    <div class="text-center">
                        <div class="text-2xl font-bold">∞</div>
                        <div class="text-blue-100 text-xs">Always Free</div>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Upload Form -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden mb-6">
            <div class="bg-gray-900 p-4 text-white">
                <h2 class="text-lg font-bold flex items-center">
                    <i class="fas fa-cloud-upload-alt mr-2"></i>Upload HTML File
                </h2>
                <p class="text-gray-300 text-sm mt-1">Share your HTML pages with full CSS and JavaScript support</p>
            </div>
            
            <div class="p-6">
                <form id="uploadForm" method="POST" enctype="multipart/form-data">
                    <div id="dropZone" class="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center cursor-pointer hover:border-gray-400 hover:bg-gray-50 transition-colors">
                        <i class="fas fa-cloud-upload-alt text-5xl text-gray-400 mb-4"></i>
                        <h3 class="text-lg font-semibold text-gray-900 mb-2">Drop your HTML file here</h3>
                        <p class="text-gray-600 mb-4">or click to browse</p>
                        <input type="file" name="file" id="fileInput" accept=".html,.htm" class="hidden" required>
                        <button type="button" onclick="document.getElementById('fileInput').click()" 
                                class="bg-gray-900 text-white px-6 py-2.5 rounded-lg hover:bg-gray-800 transition-colors font-medium inline-flex items-center">
                            <i class="fas fa-folder-open mr-2"></i>Choose File
                        </button>
                        <div class="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm text-gray-600">
                            <div class="flex items-center justify-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>External CSS & JS</span>
                            </div>
                            <div class="flex items-center justify-center">
                                <i class="fas fa-shield-alt text-blue-500 mr-2"></i>
                                <span>Secure Hosting</span>
                            </div>
                            <div class="flex items-center justify-center">
                                <i class="fas fa-infinity text-purple-500 mr-2"></i>
                                <span>100% Free</span>
                            </div>
                        </div>
                    </div>

                    <div id="fileInfo" class="hidden bg-blue-50 border border-blue-200 rounded-lg p-4 mt-4">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center flex-1 min-w-0">
                                <div class="w-12 h-12 bg-white rounded-lg flex items-center justify-center mr-4 flex-shrink-0 border border-blue-200">
                                    <i class="fas fa-file-code text-blue-500 text-xl"></i>
                                </div>
                                <div class="flex-1 min-w-0">
                                    <p class="font-semibold text-gray-900 truncate" id="fileName"></p>
                                    <p class="text-sm text-gray-600" id="fileSize"></p>
                                </div>
                            </div>
                            <button type="submit" class="bg-blue-500 text-white px-6 py-2.5 rounded-lg hover:bg-blue-600 transition-colors font-medium ml-4 whitespace-nowrap">
                                <i class="fas fa-upload mr-2"></i>Upload
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Features -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="bg-white rounded-lg border border-gray-200 p-6 text-center hover:shadow-md transition-shadow">
                <div class="w-12 h-12 bg-blue-50 rounded-lg flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-palette text-blue-500 text-xl"></i>
                </div>
                <h3 class="font-bold text-gray-900 mb-2">Full Formatting</h3>
                <p class="text-gray-600 text-sm">All CSS and JavaScript preserved perfectly</p>
            </div>
            <div class="bg-white rounded-lg border border-gray-200 p-6 text-center hover:shadow-md transition-shadow">
                <div class="w-12 h-12 bg-green-50 rounded-lg flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-shield-alt text-green-500 text-xl"></i>
                </div>
                <h3 class="font-bold text-gray-900 mb-2">Secure Storage</h3>
                <p class="text-gray-600 text-sm">Protected with security headers and validation</p>
            </div>
            <div class="bg-white rounded-lg border border-gray-200 p-6 text-center hover:shadow-md transition-shadow">
                <div class="w-12 h-12 bg-purple-50 rounded-lg flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-bolt text-purple-500 text-xl"></i>
                </div>
                <h3 class="font-bold text-gray-900 mb-2">Instant Sharing</h3>
                <p class="text-gray-600 text-sm">Get a shareable link immediately after upload</p>
            </div>
        </div>

        <!-- Info Section -->
        <div class="bg-white rounded-lg border border-gray-200 p-6 mb-6">
            <h3 class="font-bold text-gray-900 mb-4 flex items-center">
                <i class="fas fa-info-circle text-blue-500 mr-2"></i>
                How It Works
            </h3>
            <div class="space-y-3 text-sm text-gray-600">
                <div class="flex items-start">
                    <div class="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center mr-3 flex-shrink-0 mt-0.5">
                        <span class="text-blue-600 font-bold text-xs">1</span>
                    </div>
                    <div>
                        <p class="font-medium text-gray-900">Upload your HTML file</p>
                        <p class="text-gray-600">Drag and drop or click to select your HTML file (max 5MB)</p>
                    </div>
                </div>
                <div class="flex items-start">
                    <div class="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center mr-3 flex-shrink-0 mt-0.5">
                        <span class="text-green-600 font-bold text-xs">2</span>
                    </div>
                    <div>
                        <p class="font-medium text-gray-900">Get your unique link</p>
                        <p class="text-gray-600">Receive a shareable URL instantly after upload</p>
                    </div>
                </div>
                <div class="flex items-start">
                    <div class="w-6 h-6 bg-purple-100 rounded-full flex items-center justify-center mr-3 flex-shrink-0 mt-0.5">
                        <span class="text-purple-600 font-bold text-xs">3</span>
                    </div>
                    <div>
                        <p class="font-medium text-gray-900">Share with anyone</p>
                        <p class="text-gray-600">Your HTML page works perfectly with all external resources</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="text-center text-gray-600 text-sm space-y-2">
            <p class="font-medium">Powered by <span class="font-bold text-gray-900">xsukax</span> • Free HTML Hosting Platform</p>
            <p class="text-xs">
                <i class="fas fa-lock text-green-500 mr-1"></i>
                All files are validated and served securely
            </p>
        </footer>
    </main>

    <!-- Error Modal -->
    <?php if ($upload_error): ?>
    <div class="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4" id="errorModal">
        <div class="bg-white rounded-lg max-w-md w-full p-6 shadow-xl border border-gray-200 animate-scale-in">
            <div class="flex items-start mb-4">
                <div class="w-12 h-12 bg-red-50 rounded-lg flex items-center justify-center mr-4 flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-500 text-2xl"></i>
                </div>
                <div class="flex-1">
                    <h3 class="text-lg font-bold text-gray-900 mb-1"><?php echo htmlspecialchars($upload_error['title']); ?></h3>
                    <p class="text-gray-600 text-sm"><?php echo htmlspecialchars($upload_error['message']); ?></p>
                </div>
            </div>
            <div class="flex justify-end">
                <button onclick="closeModal()" class="bg-gray-900 text-white px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors font-medium">
                    Close
                </button>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Delete Confirmation Modal -->
    <div id="deleteModal" class="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-lg max-w-md w-full p-6 shadow-xl border border-gray-200 animate-scale-in">
            <div class="flex items-start mb-4">
                <div class="w-12 h-12 bg-red-50 rounded-lg flex items-center justify-center mr-4 flex-shrink-0">
                    <i class="fas fa-trash-alt text-red-500 text-2xl"></i>
                </div>
                <div class="flex-1">
                    <h3 class="text-lg font-bold text-gray-900 mb-1">Delete File?</h3>
                    <p class="text-gray-600 text-sm">This action cannot be undone. The file will be permanently deleted.</p>
                </div>
            </div>
            <div class="flex justify-end gap-3">
                <button onclick="closeDeleteModal()" class="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-300 transition-colors font-medium">
                    Cancel
                </button>
                <a id="confirmDeleteBtn" href="#" class="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition-colors font-medium">
                    Delete File
                </a>
            </div>
        </div>
    </div>

    <style>
        @keyframes fade-in {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes scale-in {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
        .animate-fade-in {
            animation: fade-in 0.3s ease-out;
        }
        .animate-scale-in {
            animation: scale-in 0.2s ease-out;
        }
    </style>

    <script>
        // Drag and drop
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const fileInfo = document.getElementById('fileInfo');
        const uploadForm = document.getElementById('uploadForm');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('border-blue-500', 'bg-blue-50');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('border-blue-500', 'bg-blue-50');
            });
        });

        dropZone.addEventListener('drop', e => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileInfo();
            }
        });

        fileInput.addEventListener('change', updateFileInfo);

        function updateFileInfo() {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                document.getElementById('fileName').textContent = file.name;
                document.getElementById('fileSize').textContent = formatBytes(file.size);
                fileInfo.classList.remove('hidden');
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Copy URL
        function copyUrl() {
            const input = document.getElementById('shareUrl');
            input.select();
            input.setSelectionRange(0, 99999);
            document.execCommand('copy');
            showNotification('Link copied to clipboard!', 'success');
        }

        // Notifications
        function showNotification(message, type = 'info') {
            const colors = {
                success: 'bg-green-500',
                error: 'bg-red-500',
                info: 'bg-blue-500'
            };
            const color = colors[type] || 'bg-blue-500';
            
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 ${color} text-white px-4 py-3 rounded-lg shadow-lg z-50 transition-all duration-300 transform translate-x-full`;
            notification.innerHTML = `<div class="flex items-center"><i class="fas fa-check-circle mr-2"></i><span>${message}</span></div>`;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.remove('translate-x-full');
                setTimeout(() => {
                    notification.classList.add('translate-x-full');
                    setTimeout(() => notification.remove(), 300);
                }, 3000);
            }, 100);
        }

        // Modal controls
        function closeModal() {
            const modal = document.getElementById('errorModal');
            if (modal) modal.remove();
        }

        function confirmDelete(url) {
            document.getElementById('confirmDeleteBtn').href = url + '&delete&confirm';
            document.getElementById('deleteModal').classList.remove('hidden');
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').classList.add('hidden');
        }

        // Form submission
        if (uploadForm) {
            uploadForm.addEventListener('submit', function() {
                const btn = this.querySelector('button[type="submit"]');
                if (btn) {
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Uploading...';
                    btn.disabled = true;
                }
            });
        }

        // Close modal on background click
        document.addEventListener('click', function(e) {
            if (e.target.id === 'errorModal' || e.target.id === 'deleteModal') {
                e.target.classList.add('hidden');
            }
        });

        // Auto-hide success messages after 10 seconds
        setTimeout(() => {
            const successMessage = document.querySelector('.animate-fade-in');
            if (successMessage && !successMessage.classList.contains('hidden')) {
                successMessage.style.transition = 'opacity 0.5s';
                successMessage.style.opacity = '0';
                setTimeout(() => {
                    successMessage.style.display = 'none';
                }, 500);
            }
        }, 10000);
    </script>
</body>
</html>