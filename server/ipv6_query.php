<?php
// 文件名: ipv6_query.php

// 设置响应头
header('Content-Type: application/json; charset=utf-8');

// 数据库配置
$servername = "localhost";
$username = "admin"; // 替换为你的数据库用户名
$password = ""; // 替换为你的数据库密码
$dbname = ""; // 替换为你的数据库名称
// 创建连接
$conn = new mysqli($servername, $username, $password, $dbname);

// 检查连接
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit();
}

// 获取并清理 UUID
$uuid = trim($_GET['uuid'] ?? '');

if (empty($uuid)) {
    http_response_code(400);
    echo json_encode(['error' => 'UUID is required']);
    exit();
}


// 使用预处理语句防止 SQL 注入
$stmt = $conn->prepare("SELECT ipv6_address FROM ipv6_records WHERE uuid = ?");
if (!$stmt) {
    http_response_code(500);
    echo json_encode(['error' => 'Prepared statement failed']);
    exit();
}

$stmt->bind_param("s", $uuid);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    echo json_encode([
        'uuid' => $uuid,
        'ipv6_address' => $row['ipv6_address']
    ]);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'UUID not found']);
}

// 关闭连接
$stmt->close();
$conn->close();
?>