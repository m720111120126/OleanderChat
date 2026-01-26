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
    echo json_encode(['error' => '数据库连接失败']);
    exit();
}

try {
    // 1. 插入一行空数据，触发自增
    // NULL 对应自增字段，'' 是为了满足语法，实际上只有一列也可以
    $sql = "INSERT INTO id_sequence () VALUES ()";
    
    if ($conn->query($sql) === TRUE) {
        // 2. 获取刚刚生成的自增ID
        $newId = $conn->insert_id;
        
        // 3. （可选）立即删除该行以保持表极小（或者保留也没关系，硬盘很便宜）
        // 如果你决定保留数据（推荐），就不需要下面这行 delete 代码。
        // 保留数据可以让你知道历史最大ID是多少。
        // $conn->query("DELETE FROM id_sequence WHERE id < $newId"); 
        
        echo json_encode(['id' => $newId]);
    } else {
        throw new Exception("Insert failed: " . $conn->error);
    }

} catch (Exception $e) {
    http_response_code(500);
    error_log("ID分配器错误: " . $e->getMessage());
    echo json_encode(['error' => 'ID分配失败']);
}

$conn->close();
?>