import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import warnings

# Игнорируем предупреждения о неверных escape-последовательностях
warnings.filterwarnings('ignore', category=SyntaxWarning)

def load_and_analyze_security_events(file_path):
    """
    Загружает и анализирует события информационной безопасности из JSON файла
    """
    print("=" * 60)
    print("АНАЛИЗ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ")
    print("=" * 60)
    
    # 1. ЗАГРУЗКА ДАННЫХ ИЗ JSON
    print("\n1. ЗАГРУЗКА ДАННЫХ ИЗ ФАЙЛА JSON")
    print("-" * 40)
    
    try:
        # Используем raw string для Windows путей
        if '\\' in file_path:
            file_path = file_path.replace('\\', '/')
        
        # Читаем JSON файл
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Извлекаем массив events из данных
        events_data = data['events']
        
        # Создаем DataFrame из списка событий
        df = pd.DataFrame(events_data)
        
        print(f"✅ Файл успешно загружен: {file_path}")
        print(f"📊 Количество событий: {len(df)}")
        print(f"📋 Столбцы в данных: {list(df.columns)}")
        
    except Exception as e:
        print(f"❌ Ошибка при загрузке файла: {e}")
        return None
    
    # 2. АНАЛИЗ ДАННЫХ
    print("\n2. АНАЛИЗ РАСПРЕДЕЛЕНИЯ СОБЫТИЙ")
    print("-" * 40)
    
    # Проверяем наличие поля signature
    if 'signature' not in df.columns:
        print("❌ Ошибка: поле 'signature' не найдено в данных!")
        return None
    
    # Преобразуем timestamp в datetime для лучшего анализа
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        df['hour'] = df['timestamp'].dt.hour
    
    # Анализ распределения событий по типам (signature)
    event_distribution = df['signature'].value_counts()
    
    print("\n📈 РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ПО ТИПАМ:")
    print("-" * 50)
    
    total_events = len(df)
    for i, (event_type, count) in enumerate(event_distribution.items(), 1):
        percentage = (count / total_events) * 100
        print(f"{i:2d}. {event_type[:60]:60s} : {count:3d} событий ({percentage:.1f}%)")
    
    print("-" * 50)
    print(f"Всего уникальных типов событий: {len(event_distribution)}")
    print(f"Всего событий: {total_events}")
    
    return df, event_distribution


def visualize_event_distribution(df, event_distribution, total_events=None):
    """
    Визуализирует распределение событий ИБ
    total_events: общее количество событий
    """

    if total_events is None:
        total_events = len(df)


    print("\n3. ВИЗУАЛИЗАЦИЯ ДАННЫХ")
    print("-" * 40)
    
    # Настройка стиля
    plt.style.use('seaborn-v0_8-darkgrid')
    sns.set_palette("husl")
    
    # Создаем фигуру
    fig = plt.figure(figsize=(15, 10))
    
    # График 1: Столбчатая диаграмма
    ax1 = plt.subplot(2, 2, 1)
    bars = ax1.bar(range(len(event_distribution)), event_distribution.values)
    ax1.set_title('РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ИБ ПО ТИПАМ', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Типы событий', fontsize=12)
    ax1.set_ylabel('Количество событий', fontsize=12)
    ax1.set_xticks(range(len(event_distribution)))
    ax1.set_xticklabels([sig[:30] + '...' if len(sig) > 30 else sig 
                         for sig in event_distribution.index], 
                        rotation=45, ha='right', fontsize=9)
    ax1.grid(True, alpha=0.3, axis='y')
    
    # Добавляем значения на столбцы
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{int(height)}', ha='center', va='bottom', fontsize=9)
    
    # График 2: Круговая диаграмма
    ax2 = plt.subplot(2, 2, 2)
    colors = plt.cm.Set3(range(len(event_distribution)))
    wedges, texts, autotexts = ax2.pie(
        event_distribution.values,
        labels=event_distribution.index,
        autopct='%1.1f%%',
        startangle=90,
        colors=colors,
        textprops={'fontsize': 9},
        wedgeprops={'edgecolor': 'black', 'linewidth': 0.5}
    )
    ax2.set_title('ДОЛЯ ТИПОВ СОБЫТИЙ', fontsize=14, fontweight='bold')
    
    # График 3: Горизонтальная барчарт
    ax3 = plt.subplot(2, 2, 3)
    y_pos = range(len(event_distribution))
    ax3.barh(y_pos, event_distribution.values)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels([sig[:40] + '...' if len(sig) > 40 else sig 
                         for sig in event_distribution.index], 
                        fontsize=9)
    ax3.set_title('РАСПРЕДЕЛЕНИЕ СОБЫТИЙ (ГОРИЗОНТАЛЬНО)', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Количество событий', fontsize=12)
    ax3.grid(True, alpha=0.3, axis='x')
    
    # График 4: Распределение по времени
    ax4 = plt.subplot(2, 2, 4)
    if 'hour' in df.columns:
        hourly_dist = df['hour'].value_counts().sort_index()
        ax4.plot(hourly_dist.index, hourly_dist.values, 
                marker='o', linewidth=2, markersize=8, color='red')
        ax4.set_title('РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ПО ЧАСАМ', fontsize=14, fontweight='bold')
        ax4.set_xlabel('Час дня', fontsize=12)
        ax4.set_ylabel('Количество событий', fontsize=12)
        ax4.set_xticks(range(0, 24, 2))
        ax4.grid(True, alpha=0.3)
        
        # Добавляем точки данных
        for hour, count in hourly_dist.items():
            ax4.text(hour, count + 0.5, str(count), 
                    ha='center', va='bottom', fontsize=9)
    else:
        # Если нет времени, показываем топ событий по-другому
        ax4.text(0.5, 0.5, 'Дополнительная статистика\nнедоступна\n(отсутствует timestamp)', 
                ha='center', va='center', fontsize=12, transform=ax4.transAxes)
        ax4.set_title('ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ', fontsize=14, fontweight='bold')
        ax4.axis('off')
    
    plt.suptitle('АНАЛИЗ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ', 
                fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()
    
    # Сохраняем график
    plt.savefig('security_events_distribution.png', dpi=300, bbox_inches='tight')
    print("✅ График сохранен как 'security_events_distribution.png'")
    
    # Дополнительная статистика (выполнится ДО показа графика)
    print("\n📊 ДОПОЛНИТЕЛЬНАЯ СТАТИСТИКА:")
    print("-" * 40)
    
    # Анализ категорий событий (по первым словам в сигнатуре)
    df['event_category'] = df['signature'].apply(lambda x: x.split()[0] if ' ' in x else x)
    category_dist = df['event_category'].value_counts()
    
    # Пересчитываем total_events
    total_events = len(df)
    
    print("\n📂 РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ (первые слова):")
    for category, count in category_dist.items():
        percentage = (count / total_events) * 100
        print(f"  {category:20s}: {count:3d} событий ({percentage:.1f}%)")
    
    # Временной анализ
    if 'date' in df.columns:
        print(f"\n📅 Период данных: с {df['date'].min()} по {df['date'].max()}")
        print(f"📅 Всего дней: {df['date'].nunique()}")
    
    if 'hour' in df.columns:
        hourly_dist = df['hour'].value_counts().sort_index()
        print(f"\n⏰ Самый активный час: {hourly_dist.idxmax()}:00 ({hourly_dist.max()} событий)")
    
    # Показываем график (после вывода статистики)
    print("\n🖼️  ОТОБРАЖЕНИЕ ГРАФИКА...")
    print("(Закройте окно графика чтобы продолжить)")
    plt.show()
    
    return True

def main():
    """
    Главная функция
    """

    file_path = r"events.json"

    # Загружаем и анализируем данные
    result = load_and_analyze_security_events(file_path)
    
    if result:
        df, event_distribution = result
        # Визуализируем данные
        visualization_success = visualize_event_distribution(df, event_distribution)
        
        if visualization_success:
            # Сохраняем результаты анализа в CSV
            event_distribution_df = pd.DataFrame({
                'signature': event_distribution.index,
                'count': event_distribution.values,
                'percentage': (event_distribution.values / len(df) * 100).round(1)
            })
            event_distribution_df.to_csv('events_analysis.csv', index=False, encoding='utf-8-sig')
            print("\n✅ Результаты анализа сохранены в 'events_analysis.csv'")
            
            # Вывод сводки
            print("\n" + "=" * 60)
            print("СВОДКА АНАЛИЗА ЗАВЕРШЕНА")
            print("=" * 60)
            print(f"✓ Проанализировано событий: {len(df)}")
            print(f"✓ Уникальных типов событий: {len(event_distribution)}")
            print(f"✓ Создан график: security_events_distribution.png")
            print(f"✓ Сохранен CSV: events_analysis.csv")
            print("\n🎉 ЗАДАНИЕ ВЫПОЛНЕНО УСПЕШНО!")

if __name__ == "__main__":
    main()
