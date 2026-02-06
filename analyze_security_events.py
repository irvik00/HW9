import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import warnings
import os

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

def save_results_to_project_folder(df, event_distribution, project_folder="results"):
    """
    Сохраняет все результаты анализа в папку проекта
    """
    # Создаем папку для результатов, если ее нет
    if not os.path.exists(project_folder):
        os.makedirs(project_folder)
        print(f"📁 Создана папка для результатов: {project_folder}")
    
    # 1. Сохраняем график
    plt.style.use('seaborn-v0_8-darkgrid')
    sns.set_palette("husl")
    
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
    
    plt.suptitle('АНАЛИЗ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ', 
                fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()
    
    # Сохраняем график в папку проекта
    graph_path = os.path.join(project_folder, 'security_events_distribution.png')
    plt.savefig(graph_path, dpi=300, bbox_inches='tight')
    plt.close()  # Закрываем график, чтобы не показывать
    print(f"✅ График сохранен: {graph_path}")
    
    # 2. Сохраняем CSV с результатами анализа
    event_distribution_df = pd.DataFrame({
        'signature': event_distribution.index,
        'count': event_distribution.values,
        'percentage': (event_distribution.values / len(df) * 100).round(1)
    })
    csv_path = os.path.join(project_folder, 'events_analysis.csv')
    event_distribution_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
    print(f"✅ Результаты анализа сохранены: {csv_path}")
    
    # 3. Сохраняем дополнительную статистику в текстовый файл
    stats_path = os.path.join(project_folder, 'analysis_summary.txt')
    with open(stats_path, 'w', encoding='utf-8') as f:
        f.write("АНАЛИЗ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Всего событий: {len(df)}\n")
        f.write(f"Уникальных типов событий: {len(event_distribution)}\n\n")
        
        f.write("РАСПРЕДЕЛЕНИЕ ПО ТИПАМ:\n")
        f.write("-" * 40 + "\n")
        for i, (event_type, count) in enumerate(event_distribution.items(), 1):
            percentage = (count / len(df)) * 100
            f.write(f"{i}. {event_type}: {count} ({percentage:.1f}%)\n")
    
    print(f"✅ Статистика сохранена: {stats_path}")
    
    return graph_path, csv_path, stats_path

def main():
    """
    Главная функция
    """

    file_path = r"D:\Work\events.json"

    # Создаем папку проекта (там где лежит скрипт)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_folder = os.path.join(script_dir, "security_analysis_results")
    
    print(f"📂 Папка проекта: {script_dir}")
    print(f"📁 Папка для результатов: {project_folder}")
    
    # Загружаем и анализируем данные
    result = load_and_analyze_security_events(file_path)
    
    if result:
        df, event_distribution = result
        
        # Сохраняем результаты в папку проекта
        graph_path, csv_path, stats_path = save_results_to_project_folder(
            df, event_distribution, project_folder
        )
        
        # Вывод сводки
        print("\n" + "=" * 60)
        print("СВОДКА АНАЛИЗА ЗАВЕРШЕНА")
        print("=" * 60)
        print(f"✓ Проанализировано событий: {len(df)}")
        print(f"✓ Уникальных типов событий: {len(event_distribution)}")
        print(f"✓ Созданные файлы находятся в папке: {project_folder}")
        print(f"  1. {os.path.basename(graph_path)} - график распределения")
        print(f"  2. {os.path.basename(csv_path)} - таблица с результатами")
        print(f"  3. {os.path.basename(stats_path)} - статистика анализа")
        print("\n🎉 ВСЕ ФАЙЛЫ УСПЕШНО СОХРАНЕНЫ В ПАПКУ ПРОЕКТА!")

if __name__ == "__main__":
    main()
