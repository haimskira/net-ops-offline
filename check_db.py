from app import app
from managers.models import AddressObject

with app.app_context():
    objs = AddressObject.query.filter(AddressObject.type != 'group').limit(5).all()
    print(f"--- Checking {len(objs)} DB Objects ---")
    for o in objs:
        print(f"Name: {o.name} | Value: {o.value}")
