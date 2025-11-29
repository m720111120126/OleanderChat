<?php
// 文件名: id_allocator.php

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

// 获取当前最大ID
$sql = "SELECT last_allocated_id FROM ids LIMIT 1";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $currentId = $row['last_allocated_id'];
} else {
    die("Error retrieving current ID");
}

// 增加ID
$newId = $currentId + 1;

// 更新数据库中的ID
$updateSql = "UPDATE ids SET last_allocated_id = $newId WHERE id = 1";
if ($conn->query($updateSql) === TRUE) {
    // 返回新ID作为响应
    header('Content-Type: application/json');
    echo json_encode(['id' => $newId]);
} else {
    die("Error updating record: " . $conn->error);
}

$conn->close();
?>


