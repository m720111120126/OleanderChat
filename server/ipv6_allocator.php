<?php
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
    echo json_encode(['error' => 'Database connection failed: ' . $conn->connect_error]);
    exit();
}

// 获取并解析输入数据
$data = json_decode(file_get_contents('php://input'), true);
$uuid = $data['uuid'] ?? '';
$ipv6_address = $data['ipv6_address'] ?? '';

// 验证输入
if (empty($uuid) || empty($ipv6_address)) {
    http_response_code(400);
    echo json_encode(['error' => 'UUID and IPv6 address are required']);
    exit();
}

// 可选：验证 UUID 和 IPv6 格式
if (!filter_var($ipv6_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid IPv6 address']);
    exit();
}

// 使用预处理语句插入或更新
$stmt = $conn->prepare("INSERT INTO ipv6_records (uuid, ipv6_address) VALUES (?, ?) ON DUPLICATE KEY UPDATE ipv6_address = VALUES(ipv6_address)");
$stmt->bind_param("ss", $uuid, $ipv6_address);

if ($stmt->execute()) {
    http_response_code(200);
    echo json_encode([
        'message' => 'Record inserted or updated successfully',
        'uuid' => $uuid,
        'ipv6_address' => $ipv6_address
    ]);
} else {
    http_response_code(500);
    echo json_encode(['error' => 'Error inserting or updating record: ' . $stmt->error]);
}

// 关闭连接
$stmt->close();
$conn->close();
?>