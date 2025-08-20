import os
import time
from datetime import datetime, timedelta
from typing import Optional


class LogRotator:
    """Простой ротатор логов с перезаписью через заданный интервал."""
    
    def __init__(self, log_file_path: str, rotation_interval: int = 86400):
        """
        Инициализация ротатора логов.
        
        Args:
            log_file_path: Путь к файлу логов
            rotation_interval: Интервал ротации в секундах (по умолчанию 24 часа)
        """
        self.log_file_path = log_file_path
        self.rotation_interval = rotation_interval
        self.last_rotation_time = self._get_file_creation_time()
        
    def _get_file_creation_time(self) -> float:
        """Получить время создания файла логов."""
        try:
            if os.path.exists(self.log_file_path):
                return os.path.getctime(self.log_file_path)
            return time.time()
        except OSError:
            return time.time()
    
    def should_rotate(self) -> bool:
        """Проверить, нужно ли выполнить ротацию логов."""
        current_time = time.time()
        time_since_last_rotation = current_time - self.last_rotation_time
        return time_since_last_rotation >= self.rotation_interval
    
    def rotate_logs(self) -> bool:
        """Выполнить ротацию логов - очистить файл."""
        try:
            # Очищаем файл логов
            with open(self.log_file_path, 'w', encoding='utf-8') as f:
                f.write(f"# Логи RSS коннектора - ротация {datetime.now().isoformat()}\n")
                f.write(f"# Файл очищен и начат заново\n\n")
            
            # Обновляем время последней ротации
            self.last_rotation_time = time.time()
            return True
            
        except Exception:
            return False
    
    def check_and_rotate(self) -> bool:
        """Проверить необходимость ротации и выполнить при необходимости."""
        if self.should_rotate():
            return self.rotate_logs()
        return False
