<?php
// 文件名: ipv6_query.php

// 数据库配置
$servername = "localhost";
$username = "admin"; // 替换为你的数据库用户名
$password = ""; // 替换为你的数据库密码
$dbname = ""; // 替换为你的数据库名称
// 创建连接
$conn = new mysqli($servername, $username, $password, $dbname);

// 检查连接
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// 获取UUID（假设通过GET请求传递）
$uuid = isset($_GET['uuid']) ? $_GET['uuid'] : '';

if (empty($uuid)) {
    header('Content-Type: application/json');
    http_response_code(400);
    echo json_encode(['error' => 'UUID is required']);
    exit();
}

// 查询UUID对应的IPv6地址
$sql = "SELECT ipv6_address FROM ipv6_records WHERE uuid = '$uuid'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    // 返回结果
    $row = $result->fetch_assoc();
    header('Content-Type: application/json');
    echo json_encode(['uuid' => $uuid, 'ipv6_address' => $row['ipv6_address']]);
} else {
    // 返回错误响应
    header('Content-Type: application/json');
    http_response_code(404);
    echo json_encode(['error' => "UUID not found"]);
}

$conn->close();
?>


