import pandas as pd

def parse_schedule(file_path):
    # Excel dosyasını başlıksız okuyoruz
    df = pd.read_excel(file_path, header=None)

    # Her günün hangi sütun aralıklarında yer aldığını tanımlıyoruz:
    day_column_ranges = {
        "Pazartesi": range(1, 9),   # sütun 1-8
        "Salı":       range(9, 17),  # sütun 9-16
        "Çarşamba":   range(17, 25), # sütun 17-24
        "Perşembe":   range(25, 33), # sütun 25-32
        "Cuma":       range(33, 41),  # sütun 33-40
        "Cumartesi":  range(41, 49)   # sütun 41-48
    }

    # 3. satır (df.iloc[2]) her günün ders saatlerinin zaman aralıklarını içeriyor
    times = {}
    for day, col_range in day_column_ranges.items():
        times[day] = {}
        hour_idx = 1
        for col in col_range:
            cell_value = df.iloc[2, col]
            times[day][hour_idx] = str(cell_value).strip() if pd.notna(cell_value) else ""
            hour_idx += 1

    schedule = []

    # 4. satırdan itibaren her satır bir sınıfı temsil ediyor (ilk sütun sınıf adı)
    for row_idx in range(3, df.shape[0]):
        class_name = df.iloc[row_idx, 0]
        if pd.isna(class_name):
            continue  # Sınıf adı yoksa atla
        class_name = str(class_name).strip()

        # Her gün için işlemleri yapalım
        for day, col_range in day_column_ranges.items():
            # O güne ait sütun indekslerini alalım (örneğin Pazartesi: 1-8)
            col_indices = list(col_range)
            n = len(col_indices)
            # İlgili hücrelerdeki değerleri (varsa) listeye ekleyelim; boş hücreler None olarak işaretlensin
            values = []
            for col in col_indices:
                cell_val = df.iloc[row_idx, col]
                text = str(cell_val).strip() if pd.notna(cell_val) and str(cell_val).strip() != "" else None
                values.append(text)

            # Merged hücrelerden dolayı, boş olanları önceki hücre değeriyle dolduralım (forward fill)
            for i in range(1, n):
                if values[i] is None and values[i-1] is not None:
                    values[i] = values[i-1]

            # Her saat için ayrı kayıt oluşturuyoruz (forward fill uygulandıktan sonra bile)
            for idx, value in enumerate(values, start=1):
                if value is not None:
                    lines = value.split('\n')
                    subject = lines[0].strip() if len(lines) > 0 else ""
                    teacher = lines[1].strip() if len(lines) > 1 else ""
                    
                    schedule.append({
                        "day": day,
                        "class": class_name,
                        "hour_index": idx,
                        "time_range": times[day][idx],
                        "subject": subject,
                        "teacher": teacher
                    })
                else:
                    # Eğer hücre gerçekten boşsa, istersek boş giriş oluşturabiliriz; burada atlıyoruz.
                    pass

    return schedule

def main():
    file_path = "C:/Users/user/Desktop/SinifCarsafListesi.xlsx"  # Dosyanızın yolunu belirtin
    schedule_data = parse_schedule(file_path)
    return(schedule_data)


if __name__ == "__main__":
    main()
