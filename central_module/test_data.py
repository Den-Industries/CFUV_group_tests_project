from database import SessionLocal
import models

def create_test_data():
    db = SessionLocal()
    
    try:
        # Создаём тестовый тест
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        
        if admin:
            # Проверяем, есть ли уже тест
            existing_test = db.query(models.Test).filter(models.Test.title == "Основы Python").first()
            
            if not existing_test:
                test = models.Test(
                    title="Основы Python",
                    description="Базовый тест по языку программирования Python",
                    created_by=admin.id
                )
                db.add(test)
                db.commit()
                db.refresh(test)
                
                # Добавляем вопросы
                questions_data = [
                    {
                        "text": "Какой тип данных в Python является неизменяемым?",
                        "type": "single_choice",
                        "points": 2,
                        "answers": [
                            {"text": "Список (list)", "correct": False},
                            {"text": "Словарь (dict)", "correct": False},
                            {"text": "Кортеж (tuple)", "correct": True},
                            {"text": "Множество (set)", "correct": False}
                        ]
                    },
                    {
                        "text": "Что выведет print(type([]))?",
                        "type": "single_choice",
                        "points": 1,
                        "answers": [
                            {"text": "<class 'list'>", "correct": True},
                            {"text": "<class 'array'>", "correct": False},
                            {"text": "<class 'tuple'>", "correct": False},
                            {"text": "<class 'dict'>", "correct": False}
                        ]
                    }
                ]
                
                for i, q_data in enumerate(questions_data):
                    question = models.Question(
                        test_id=test.id,
                        question_text=q_data["text"],
                        question_type=q_data["type"],
                        order_index=i,
                        points=q_data["points"]
                    )
                    db.add(question)
                    db.commit()
                    db.refresh(question)
                    
                    for j, a_data in enumerate(q_data["answers"]):
                        answer = models.Answer(
                            question_id=question.id,
                            answer_text=a_data["text"],
                            is_correct=a_data["correct"],
                            order_index=j
                        )
                        db.add(answer)
                
                db.commit()
                print("✅ Тестовые данные созданы успешно!")
            else:
                print("ℹ️ Тестовые данные уже существуют")
    except Exception as e:
        print(f"❌ Ошибка при создании тестовых данных: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_test_data()
