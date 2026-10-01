import asyncio
from sqlalchemy import select
from argon2 import PasswordHasher
from .db import SessionLocal
from .models import User,Profile,Course,Skill,Interest,Role
ph=PasswordHasher()
async def main():
 async with SessionLocal() as db:
  if await db.scalar(select(User.id).limit(1)): return
  course=Course(name='Software Development'); db.add(course)
  skills=[Skill(name=x,category='Technology') for x in ['Python','JavaScript','React','SQL','Figma','Marketing']]; interests=[Interest(name=x) for x in ['AI','Climate tech','Fintech','Startups']];db.add_all(skills+interests);await db.flush()
  for i,(name,email,role) in enumerate([('Admin','admin@example.com',Role.software_developer),('Priya','priya@example.com',Role.business_developer),('Sam','sam@example.com',Role.software_developer)]):
   u=User(email=email,password_hash=ph.hash('password123'),display_name=name,first_name=name,is_admin=i==0);db.add(u);await db.flush();p=Profile(user_id=u.id,role=role,course_id=course.id,bio='Demo cohort member',looking_for='Someone to build a useful project with',profile_complete=True);p.skills=[skills[i],skills[2]];p.interests=[interests[i]];db.add(p)
  await db.commit()
if __name__=='__main__':asyncio.run(main())
