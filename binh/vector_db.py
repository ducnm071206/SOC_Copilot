import chromadb

def init_vector_db():
    # Khởi tạo ChromaDB client lưu tại thư mục local 'chroma_sop_db'
    client = chromadb.PersistentClient(path="chroma_sop_db")
    
    # Tạo hoặc lấy collection chứa các bài SOP
    collection = client.get_or_create_collection(name="soc_sops")
    
    # Thêm dữ liệu SOP mẫu vào database (sau này bạn có thể thay bằng 8 bài SOP thực tế của Tài)
    sops = [
        {
            "id": "sop_ssh",
            "text": "SOP Xử lý SSH Brute Force: Khi phát hiện nhiều lần đăng nhập sai từ một IP, Analyst cần lập tức kiểm tra lịch sử auth.log, thực hiện chặn IP độc hại trên tường lửa bằng lệnh iptables hoặc cấu hình block trên Wazuh, sau đó thông báo cho chủ tài khoản.",
            "metadata": {"category": "Brute Force", "severity": "High"}
        },
        {
            "id": "sop_sqli",
            "text": "SOP Xử lý SQL Injection: Khi phát hiện request chứa mã độc SQLi qua tham số URL hoặc POST, kiểm tra log ứng dụng web, xác định xem database có bị truy xuất trái phép không, cô lập endpoint hoặc vá ngay lỗ hổng trong mã nguồn source code.",
            "metadata": {"category": "Web Attack", "severity": "Critical"}
        }
    ]
    
    # Nạp vào ChromaDB nếu collection đang trống
    if collection.count() == 0:
        collection.add(
            documents=[sop["text"] for sop in sops],
            metadatas=[sop["metadata"] for sop in sops],
            ids=[sop["id"] for sop in sops]
        )
        print("Đã nạp thành công các bài SOP mẫu vào ChromaDB!")
    else:
        print(f"ChromaDB đã có sẵn {collection.count()} bài SOP.")

    return collection

if __name__ == "__main__":
    init_vector_db()