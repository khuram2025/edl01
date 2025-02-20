source venv/bin/activate
cd ch_syslog
python manage.py runserver 0.0.0.0:8000

python manage.py migrate

python manage.py createsuperuser

curl -X GET "localhost:9200/_cat/indices?v"


