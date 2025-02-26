import re
from collections import defaultdict
from datetime import datetime

# Функция для чтения логов из файла
def read_logs(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

# Функция для парсинга записей логов
def parse_log_line(line):
    # Пример парсинга access.log Nginx с использованием регулярных выражений
    log_pattern = r'(?P<ip>[0-9\.]+) - - \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+|-)'
    match = re.match(log_pattern, line)
    if match:
        data = match.groupdict()
        # Преобразование времени в объект datetime
        data["datetime"] = datetime.strptime(data["datetime"], "%d/%b/%Y:%H:%M:%S %z")
        return data
    return None

# Функция анализа подозрительной активности
def analyze_logs(log_lines, failed_login_attempts_threshold=5, traffic_threshold=10000000, suspicious_ips=set()):
    failed_logins = defaultdict(int)
    ip_traffic = defaultdict(int)
    suspicious_activities = []
    
    for line in log_lines:
        log = parse_log_line(line)
        if log:
            ip = log['ip']
            status = log['status']
            size = int(log['size']) if log['size'].isdigit() else 0
            
            # Считаем неудачные попытки входа (статус HTTP 401/403)
            if status in {'401', '403'}:
                failed_logins[ip] += 1
                if failed_logins[ip] > failed_login_attempts_threshold:
                    suspicious_activities.append(
                        f"Подозрительная активность: много неудачных попыток входа с IP {ip}"
                    )
            
            # Считаем трафик с каждого IP
            ip_traffic[ip] += size
            if ip_traffic[ip] > traffic_threshold:
                suspicious_activities.append(
                    f"Подозрительная активность: большой трафик ({ip_traffic[ip]} байт) с IP {ip}"
                )
            
            # Фиксируем известные подозрительные IP-адреса
            if ip in suspicious_ips:
                suspicious_activities.append(
                    f"Подозрительная активность: обращение с известного подозрительного IP {ip}"
                )
    
    return suspicious_activities

# Основная функция
def main():
    log_file = "access.log"  # Укажите путь к вашему лог-файлу
    known_suspicious_ips = {"192.168.1.100", "203.0.113.42"}  # Пример добавления подозрительных IP
    
    try:
        log_lines = read_logs(log_file)
        activities = analyze_logs(log_lines, suspicious_ips=known_suspicious_ips)
        
        if activities:
            print("Обнаружена подозрительная активность:")
            for activity in activities:
                print(f"- {activity}")
        else:
            print("Подозрительной активности не обнаружено.")
    except FileNotFoundError:
        print("Файл логов не найден. Проверьте путь к файлу.")

if __name__ == "__main__":
    main()
