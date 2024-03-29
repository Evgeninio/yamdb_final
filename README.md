[![Workflow](https://github.com/Evgeninio/yamdb_final/actions/workflows/yamdb_workflow.yml/badge.svg)](https://github.com/Evgeninio/yamdb_final/actions/workflows/yamdb_workflow.yml)
# api_yamdb
api_yamdb

## Коротко о проекте

    Проект собирает отзывы пользователей на различные произведения.

    # Алгоритм регистрации пользователей
    1. Пользователь отправляет POST-запрос на добавление нового пользователя с параметрами `email` и `username` на эндпоинт `/api/v1/auth/signup/`.
    2. **YaMDB** отправляет письмо с кодом подтверждения (`confirmation_code`) на адрес  `email`.
    3. Пользователь отправляет POST-запрос с параметрами `username` и `confirmation_code` на эндпоинт `/api/v1/auth/token/`, в ответе на запрос ему приходит `token` (JWT-токен).
    4. При желании пользователь отправляет PATCH-запрос на эндпоинт `/api/v1/users/me/` и заполняет поля в своём профайле (описание полей — в документации).

    # Пользовательские роли
    - **Аноним** — может просматривать описания произведений, читать отзывы и комментарии.
    - **Аутентифицированный пользователь** (`user`) — может, как и **Аноним**, читать всё, дополнительно он может публиковать отзывы и ставить оценку произведениям (фильмам/книгам/песенкам), может комментировать чужие отзывы; может редактировать и удалять **свои** отзывы и комментарии. Эта роль присваивается по умолчанию каждому новому пользователю.
    - **Модератор** (`moderator`) — те же права, что и у **Аутентифицированного пользователя** плюс право удалять **любые** отзывы и комментарии.
    - **Администратор** (`admin`) — полные права на управление всем контентом проекта. Может создавать и удалять произведения, категории и жанры. Может назначать роли пользователям. 
    - **Суперюзер Django** — обладет правами администратора (`admin`)

## Как запустить проект:

Клонировать репозиторий и перейти в него в командной строке:

```
git clone https://github.com/Gwynrey/api_final_yatube.git
```

```
cd api_yamdb
```

Cоздать и активировать виртуальное окружение:

```
python -m venv venv
```

```
source venv/Scripts/activate
```

Установить зависимости из файла requirements.txt:

```
python -m pip install --upgrade pip
```

```
pip install -r requirements.txt
```

Выполнить миграции:

```
python manage.py makemigrations users
python manage.py makemigrations reviews
python manage.py migrate
```

Запустить проект:

```
python manage.py runserver

```


## Как залить тестовую базу данных:

```
python manage.py load_users_data
python manage.py load_category_data
python manage.py load_comments_data
python manage.py load_genre_data
python manage.py load_review_data
python manage.py load_title_data

```


## Авторы:


Afanasev Evgenii - [Evgeninio](https://github.com/Evgeninio)

[Api/v1](http://51.250.101.162/api/v1/)

[Admin](http://51.250.101.162/admin)

[Redoc](http://51.250.101.162/redoc)

