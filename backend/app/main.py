import hashlib,secrets,uuid
from datetime import datetime,timezone,timedelta
from typing import Optional
from fastapi import FastAPI,Depends,HTTPException,Request,Response,UploadFile,File,WebSocket,WebSocketDisconnect,Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel,EmailStr,Field
from argon2 import PasswordHasher
from sqlalchemy import select,or_,and_,func,delete
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from .db import get_db
from .config import settings
from .models import *
ph=PasswordHasher(); app=FastAPI(title='Cohort Connect',docs_url='/api/v1/docs')
app.add_middleware(CORSMiddleware,allow_origins=[settings.frontend_origin],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
class APIError(Exception):
 def __init__(self,status,code,message,fields=None): self.status=status; self.code=code; self.message=message; self.fields=fields
@app.exception_handler(APIError)
async def api_error(_,e):
 d={'code':e.code,'message':e.message};
 if e.fields is not None:d['fields']=e.fields
 return JSONResponse({'error':d},status_code=e.status)
@app.exception_handler(Exception)
async def internal(_,e): return JSONResponse({'error':{'code':'internal_error','message':'Something went wrong.'}},status_code=500)
def h(s:str): return hashlib.sha256(s.encode()).digest()
def user_summary(u): return {'id':str(u.id),'display_name':u.display_name,'has_photo':bool(u.profile and u.profile.photo_id),'photo_url':f'/api/v1/users/{u.id}/photo' if u.profile and u.profile.photo_id else None}
def ref(x): return {'id':str(x.id),'name':x.name} if x else None
def profile_json(u,private=False):
 p=u.profile; d={'id':str(u.id),'display_name':u.display_name,'first_name':u.first_name,'is_admin':u.is_admin,'created_at':u.created_at.isoformat(),'profile':{'bio':p.bio,'role':p.role.value if p.role else None,'course':ref(p.course),'looking_for':p.looking_for,'skills':[ref(x) for x in p.skills],'interests':[ref(x) for x in p.interests],'profile_complete':p.profile_complete,'has_photo':bool(p.photo_id),'photo_url':f'/api/v1/users/{u.id}/photo' if p.photo_id else None}}
 if private:d.update(email=u.email,is_active=u.is_active)
 return d
async def load_user(db,uid): return (await db.execute(select(User).where(User.id==uid).options(selectinload(User.profile).selectinload(Profile.skills),selectinload(User.profile).selectinload(Profile.interests),selectinload(User.profile).selectinload(Profile.course)))).scalar_one_or_none()
async def current_user(request:Request,db:AsyncSession=Depends(get_db)):
 tok=request.cookies.get('session')
 if not tok: raise APIError(401,'unauthenticated','Sign in to continue.')
 s=(await db.execute(select(Session).where(Session.token_hash==h(tok)))).scalar_one_or_none()
 if not s or s.expires_at<datetime.now(timezone.utc): raise APIError(401,'session_expired','Your session has expired.')
 u=await load_user(db,s.user_id)
 if not u or not u.is_active: raise APIError(403,'account_deactivated','This account is deactivated.')
 if request.method in {'POST','PUT','PATCH','DELETE'}:
  csrf=request.headers.get('X-CSRF-Token','')
  if h(csrf)!=s.csrf_token: raise APIError(403,'csrf_failed','Security token missing or invalid.')
 s.last_used_at=datetime.now(timezone.utc); s.expires_at=datetime.now(timezone.utc)+timedelta(days=7); await db.commit(); return u
async def admin(u:User=Depends(current_user)):
 if not u.is_admin: raise APIError(403,'forbidden','Admin access required.')
 return u
async def create_session(db,u,response):
 token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); db.add(Session(user_id=u.id,token_hash=h(token),csrf_token=h(csrf),expires_at=datetime.now(timezone.utc)+timedelta(days=7))); await db.commit(); response.set_cookie('session',token,httponly=True,samesite='lax',secure=settings.environment=='production',max_age=604800,path='/'); response.headers['X-CSRF-Token']=csrf
class Register(BaseModel): email:EmailStr; password:str=Field(min_length=8); display_name:str=Field(min_length=1,max_length=80)
class Login(BaseModel): email:EmailStr; password:str
@app.get('/api/v1/health')
async def health(db:AsyncSession=Depends(get_db)): await db.execute(select(1)); return {'status':'ok'}
@app.post('/api/v1/auth/register',status_code=201)
async def register(b:Register,response:Response,db:AsyncSession=Depends(get_db)):
 if (await db.execute(select(User).where(User.email==b.email))).scalar_one_or_none(): raise APIError(409,'email_taken','That email is already registered.')
 u=User(email=str(b.email),password_hash=ph.hash(b.password),display_name=b.display_name.strip(),first_name=b.display_name.strip().split()[0]); db.add(u); await db.flush(); db.add(Profile(user_id=u.id)); await db.commit(); u=await load_user(db,u.id); await create_session(db,u,response); return profile_json(u,True)
@app.post('/api/v1/auth/login')
async def login(b:Login,response:Response,db:AsyncSession=Depends(get_db)):
 u=(await db.execute(select(User).where(User.email==b.email))).scalar_one_or_none()
 try: ok=bool(u and ph.verify(u.password_hash,b.password))
 except: ok=False
 if not ok: raise APIError(401,'invalid_credentials','Email or password is incorrect.')
 if not u.is_active: raise APIError(403,'account_deactivated','This account is deactivated.')
 u.last_login_at=datetime.now(timezone.utc); await db.commit(); u=await load_user(db,u.id); await create_session(db,u,response); return profile_json(u,True)
@app.post('/api/v1/auth/logout',status_code=204)
async def logout(request:Request,response:Response,db:AsyncSession=Depends(get_db)):
 tok=request.cookies.get('session');
 if tok: await db.execute(delete(Session).where(Session.token_hash==h(tok))); await db.commit()
 response.delete_cookie('session',path='/')
@app.get('/api/v1/users/me')
async def me(u:User=Depends(current_user)): return profile_json(u,True)
@app.get('/api/v1/users/{uid}')
async def public_user(uid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 x=await load_user(db,uid)
 if not x or not x.is_active: raise APIError(404,'not_found','User not found.')
 return profile_json(x)
class ProfilePatch(BaseModel): display_name:Optional[str]=Field(None,max_length=80); bio:Optional[str]=Field(None,max_length=500); role:Optional[Role]=None; course_id:Optional[uuid.UUID]=None; looking_for:Optional[str]=Field(None,max_length=300); skill_ids:Optional[list[uuid.UUID]]=Field(None,max_length=20); interest_ids:Optional[list[uuid.UUID]]=Field(None,max_length=20)
@app.patch('/api/v1/users/me')
async def patch_profile(b:ProfilePatch,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 p=u.profile
 if b.display_name is not None: u.display_name=b.display_name.strip()
 if b.bio is not None:p.bio=b.bio.strip()
 if b.role is not None:p.role=b.role
 if b.course_id is not None:
  c=await db.get(Course,b.course_id)
  if not c:raise APIError(422,'validation_error','Some fields need attention.',{'course_id':'Unknown course.'})
  p.course_id=c.id
 if b.looking_for is not None:p.looking_for=b.looking_for.strip()
 if b.skill_ids is not None:
  xs=(await db.execute(select(Skill).where(Skill.id.in_(b.skill_ids)))).scalars().all()
  if len(xs)!=len(set(b.skill_ids)):raise APIError(422,'validation_error','Some fields need attention.',{'skill_ids':'Unknown skill.'})
  p.skills=list(xs)
 if b.interest_ids is not None:
  xs=(await db.execute(select(Interest).where(Interest.id.in_(b.interest_ids)))).scalars().all(); p.interests=list(xs)
 p.profile_complete=bool(p.role and p.skills); await db.commit(); return profile_json(await load_user(db,u.id),True)
@app.get('/api/v1/courses')
async def courses(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): return [ref(x) for x in (await db.execute(select(Course).order_by(Course.name))).scalars()]
@app.get('/api/v1/skills')
async def skills(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): return [{'id':str(x.id),'name':x.name,'category':x.category} for x in (await db.execute(select(Skill).order_by(Skill.name))).scalars()]
@app.get('/api/v1/interests')
async def interests(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): return [ref(x) for x in (await db.execute(select(Interest).order_by(Interest.name))).scalars()]
def sniff(data):
 if data.startswith(b'\xff\xd8\xff'):return 'image/jpeg'
 if data.startswith(b'\x89PNG\r\n\x1a\n'):return 'image/png'
 if data[:4]==b'RIFF' and data[8:12]==b'WEBP':return 'image/webp'
@app.post('/api/v1/users/me/photo')
async def photo_upload(file:UploadFile=File(...),u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 data=await file.read(2097153)
 if len(data)>2097152:raise APIError(413,'file_too_large','Photo must be 2 MB or smaller.')
 ct=sniff(data)
 if not ct:raise APIError(415,'unsupported_media_type','Use JPEG, PNG or WebP.')
 if u.profile.photo_id: await db.execute(delete(Photo).where(Photo.id==u.profile.photo_id))
 p=Photo(user_id=u.id,content_type=ct,byte_size=len(data),data=data); db.add(p); await db.flush(); u.profile.photo_id=p.id; await db.commit(); return {'photo_url':'/api/v1/users/me/photo'}
@app.delete('/api/v1/users/me/photo',status_code=204)
async def photo_delete(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 if u.profile.photo_id: await db.execute(delete(Photo).where(Photo.id==u.profile.photo_id)); u.profile.photo_id=None; await db.commit()
@app.get('/api/v1/users/{uid}/photo')
async def photo_get(uid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 x=await load_user(db,uid)
 if not x or not x.profile.photo_id:raise APIError(404,'not_found','Photo not found.')
 p=await db.get(Photo,x.profile.photo_id); return Response(p.data,media_type=p.content_type,headers={'Cache-Control':'private, max-age=86400','ETag':hashlib.sha256(p.data).hexdigest()})
@app.get('/api/v1/users/me/photo')
async def my_photo(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): return await photo_get(u.id,u,db)
def score(viewer,cand):
 shared_s={x.name for x in viewer.profile.skills}&{x.name for x in cand.profile.skills}; shared_i={x.name for x in viewer.profile.interests}&{x.name for x in cand.profile.interests}; reasons=[]; n=0
 if viewer.profile.role and cand.profile.role and viewer.profile.role!=cand.profile.role:n+=30;reasons.append('Your roles complement each other.')
 if shared_s:n+=min(30,10*len(shared_s));reasons.append('Shared skills: '+', '.join(sorted(shared_s))+'.')
 if shared_i:n+=min(15,5*len(shared_i));reasons.append('Shared interests: '+', '.join(sorted(shared_i))+'.')
 if viewer.profile.course_id and viewer.profile.course_id==cand.profile.course_id:n+=20;reasons.append('You are on the same course.')
 return n,reasons
@app.get('/api/v1/matches')
async def matches(limit:int=20,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 if not u.profile.profile_complete:raise APIError(403,'profile_incomplete','Choose a role and add at least one skill before browsing matches.')
 users=(await db.execute(select(User).where(User.id!=u.id,User.is_active==True).options(selectinload(User.profile).selectinload(Profile.skills),selectinload(User.profile).selectinload(Profile.interests),selectinload(User.profile).selectinload(Profile.course)).limit(200))).scalars().all(); out=[]
 for x in users:
  if not x.profile or not x.profile.profile_complete:continue
  s,r=score(u,x); out.append({'user':profile_json(x),'score':s,'reasons':r})
 out.sort(key=lambda x:(-x['score'],x['user']['id'])); return {'items':out[:min(limit,50)],'next_cursor':None}
class ConnCreate(BaseModel): receiver_id:uuid.UUID; message:Optional[str]=Field(None,max_length=300)
@app.post('/api/v1/connections',status_code=201)
async def conn_create(b:ConnCreate,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 if not u.profile.profile_complete:raise APIError(403,'profile_incomplete','Complete your profile first.')
 if b.receiver_id==u.id:raise APIError(422,'validation_error','You cannot connect to yourself.')
 r=await load_user(db,b.receiver_id)
 if not r or not r.is_active:raise APIError(404,'not_found','User not found.')
 if not r.profile.profile_complete:raise APIError(422,'receiver_profile_incomplete','That profile is incomplete.')
 old=(await db.execute(select(ConnectionRequest).where(or_(and_(ConnectionRequest.sender_id==u.id,ConnectionRequest.receiver_id==r.id),and_(ConnectionRequest.sender_id==r.id,ConnectionRequest.receiver_id==u.id))))).scalar_one_or_none()
 if old:raise APIError(409,'already_exists','A connection request already exists.')
 c=ConnectionRequest(sender_id=u.id,receiver_id=r.id,message=b.message); db.add(c); await db.flush(); db.add(Notification(user_id=r.id,type='connection_requested',actor_id=u.id,connection_request_id=c.id,data={'actor_name':u.display_name,'url':'/connections'})); await db.commit(); return {'id':str(c.id),'status':c.status.value,'sender':user_summary(u),'receiver':user_summary(r),'message':c.message,'created_at':c.created_at.isoformat()}
@app.get('/api/v1/connections')
async def connections(filter:Optional[str]=None,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 q=select(ConnectionRequest).where(or_(ConnectionRequest.sender_id==u.id,ConnectionRequest.receiver_id==u.id)).order_by(ConnectionRequest.created_at.desc()); xs=(await db.execute(q)).scalars().all(); return [{'id':str(x.id),'sender_id':str(x.sender_id),'receiver_id':str(x.receiver_id),'status':x.status.value,'message':x.message,'created_at':x.created_at.isoformat()} for x in xs if not filter or (filter=='received' and x.receiver_id==u.id and x.status==ConnStatus.pending) or (filter=='sent' and x.sender_id==u.id and x.status==ConnStatus.pending) or (filter=='connected' and x.status==ConnStatus.accepted)]
class Transition(BaseModel): action:str
@app.patch('/api/v1/connections/{cid}')
async def conn_transition(cid:uuid.UUID,b:Transition,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 c=await db.get(ConnectionRequest,cid)
 if not c or u.id not in {c.sender_id,c.receiver_id}:raise APIError(404,'not_found','Connection not found.')
 if u.id!=c.receiver_id:raise APIError(403,'forbidden','Only the receiver can respond.')
 if c.status!=ConnStatus.pending or b.action not in {'accept','decline'}:raise APIError(409,'invalid_transition','That transition is not allowed.')
 c.status=ConnStatus.accepted if b.action=='accept' else ConnStatus.declined; c.responded_at=datetime.now(timezone.utc); c.responded_by=u.id
 if c.status==ConnStatus.accepted: db.add(Thread(connection_request_id=c.id))
 db.add(Notification(user_id=c.sender_id,type=f'connection_{c.status.value}',actor_id=u.id,connection_request_id=c.id,data={'actor_name':u.display_name,'url':'/connections'})); await db.commit(); return {'id':str(c.id),'status':c.status.value}
@app.delete('/api/v1/connections/{cid}',status_code=204)
async def conn_delete(cid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 c=await db.get(ConnectionRequest,cid)
 if not c or c.sender_id!=u.id:raise APIError(404,'not_found','Connection not found.')
 if c.status!=ConnStatus.pending:raise APIError(409,'invalid_transition','Only pending requests can be withdrawn.')
 await db.delete(c); await db.commit()
async def thread_for(db,tid,uid):
 t=await db.get(Thread,tid)
 if not t:raise APIError(404,'not_found','Thread not found.')
 c=await db.get(ConnectionRequest,t.connection_request_id)
 if c.status!=ConnStatus.accepted or uid not in {c.sender_id,c.receiver_id}:raise APIError(404,'not_found','Thread not found.')
 return t,c
@app.get('/api/v1/threads')
async def threads(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 xs=(await db.execute(select(Thread,ConnectionRequest).join(ConnectionRequest,Thread.connection_request_id==ConnectionRequest.id).where(ConnectionRequest.status==ConnStatus.accepted,or_(ConnectionRequest.sender_id==u.id,ConnectionRequest.receiver_id==u.id)))).all(); return [{'id':str(t.id),'connection_request_id':str(c.id),'other_user_id':str(c.receiver_id if c.sender_id==u.id else c.sender_id)} for t,c in xs]
@app.get('/api/v1/threads/{tid}/messages')
async def messages(tid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 await thread_for(db,tid,u.id); xs=(await db.execute(select(Message).where(Message.thread_id==tid).order_by(Message.created_at,Message.id).limit(50))).scalars().all(); rr=await db.get(ReadReceipt,(tid,u.id));
 if not rr:db.add(ReadReceipt(thread_id=tid,user_id=u.id,last_read_at=datetime.now(timezone.utc)))
 else:rr.last_read_at=datetime.now(timezone.utc)
 await db.commit(); return {'items':[{'id':str(x.id),'sender_id':str(x.sender_id),'body':x.body,'created_at':x.created_at.isoformat()} for x in xs],'next_cursor':None}
class Msg(BaseModel): body:str=Field(min_length=1,max_length=2000)
@app.post('/api/v1/threads/{tid}/messages',status_code=201)
async def send_message(tid:uuid.UUID,b:Msg,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 _,c=await thread_for(db,tid,u.id); m=Message(thread_id=tid,sender_id=u.id,body=b.body.strip()); db.add(m); other=c.receiver_id if c.sender_id==u.id else c.sender_id; db.add(Notification(user_id=other,type='new_message',actor_id=u.id,thread_id=tid,data={'actor_name':u.display_name,'url':f'/messages/{tid}'})); await db.commit(); return {'id':str(m.id),'sender_id':str(u.id),'body':m.body,'created_at':m.created_at.isoformat()}
class IdeaCreate(BaseModel): title:str=Field(min_length=1,max_length=120); description:str=Field(min_length=50,max_length=2000); category:IdeaCategory; skills_needed:list[str]=Field(default_factory=list,max_length=20); course_id:Optional[uuid.UUID]=None
@app.get('/api/v1/ideas')
async def ideas(u:User=Depends(current_user),db:AsyncSession=Depends(get_db),open_only:bool=True,search:Optional[str]=None):
 q=select(ProjectIdea).order_by(ProjectIdea.created_at.desc());
 if open_only:q=q.where(ProjectIdea.is_open==True)
 if search:q=q.where(or_(ProjectIdea.title.ilike(f'%{search}%'),ProjectIdea.description.ilike(f'%{search}%')))
 xs=(await db.execute(q.limit(50))).scalars().all(); out=[]
 for x in xs:
  au=await load_user(db,x.author_id); count=await db.scalar(select(func.count()).select_from(IdeaInterest).where(IdeaInterest.idea_id==x.id)); mine=await db.get(IdeaInterest,(x.id,u.id)); out.append({'id':str(x.id),'title':x.title,'description':x.description,'category':x.category.value,'skills_needed':x.skills_needed,'is_open':x.is_open,'interest_count':count,'author':user_summary(au),'viewer_has_interested':bool(mine),'created_at':x.created_at.isoformat()})
 return {'items':out,'next_cursor':None}
@app.post('/api/v1/ideas',status_code=201)
async def idea_create(b:IdeaCreate,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 if not u.profile.profile_complete:raise APIError(403,'profile_incomplete','Complete your profile first.')
 x=ProjectIdea(author_id=u.id,title=b.title.strip(),description=b.description.strip(),category=b.category,skills_needed=b.skills_needed,course_id=b.course_id or u.profile.course_id); db.add(x); await db.commit(); return {'id':str(x.id),'title':x.title}
@app.post('/api/v1/ideas/{iid}/interest')
async def idea_interest(iid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 if not u.profile.profile_complete:raise APIError(403,'profile_incomplete','Complete your profile first.')
 x=await db.get(ProjectIdea,iid)
 if not x:raise APIError(404,'not_found','Idea not found.')
 if x.author_id==u.id:raise APIError(422,'validation_error','You cannot express interest in your own idea.')
 if not x.is_open:raise APIError(409,'idea_closed','This idea is closed.')
 old=await db.get(IdeaInterest,(iid,u.id))
 if old:return {'idea_id':str(iid),'user_id':str(u.id),'created_at':old.created_at.isoformat()}
 ii=IdeaInterest(idea_id=iid,user_id=u.id);db.add(ii);db.add(Notification(user_id=x.author_id,type='idea_interest',actor_id=u.id,project_idea_id=iid,data={'actor_name':u.display_name,'url':f'/ideas/{iid}'}));await db.commit();return {'idea_id':str(iid),'user_id':str(u.id),'created_at':ii.created_at.isoformat()}
@app.delete('/api/v1/ideas/{iid}/interest',status_code=204)
async def idea_uninterest(iid:uuid.UUID,u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): await db.execute(delete(IdeaInterest).where(IdeaInterest.idea_id==iid,IdeaInterest.user_id==u.id));await db.commit()
@app.get('/api/v1/notifications')
async def notifications(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 xs=(await db.execute(select(Notification).where(Notification.user_id==u.id).order_by(Notification.created_at.desc()).limit(50))).scalars().all(); unread=sum(x.read_at is None for x in xs); return {'items':[{'id':str(x.id),'type':x.type,'data':x.data,'read_at':x.read_at.isoformat() if x.read_at else None,'created_at':x.created_at.isoformat()} for x in xs],'unread_count':unread,'next_cursor':None}
@app.get('/api/v1/notifications/unread-count')
async def unread(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)): return {'unread_count':await db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id==u.id,Notification.read_at==None))}
@app.patch('/api/v1/notifications/read-all',status_code=204)
async def read_all(u:User=Depends(current_user),db:AsyncSession=Depends(get_db)):
 xs=(await db.execute(select(Notification).where(Notification.user_id==u.id,Notification.read_at==None))).scalars().all(); now=datetime.now(timezone.utc)
 for x in xs:x.read_at=now
 await db.commit()
@app.get('/api/v1/admin/overview')
async def admin_overview(a:User=Depends(admin),db:AsyncSession=Depends(get_db)): return {'total_users':await db.scalar(select(func.count()).select_from(User)),'active_users':await db.scalar(select(func.count()).select_from(User).where(User.is_active==True)),'connections':await db.scalar(select(func.count()).select_from(ConnectionRequest).where(ConnectionRequest.status==ConnStatus.accepted)),'project_ideas':await db.scalar(select(func.count()).select_from(ProjectIdea))}
@app.get('/api/v1/admin/users')
async def admin_users(a:User=Depends(admin),db:AsyncSession=Depends(get_db)): return [{'id':str(x.id),'email':x.email,'display_name':x.display_name,'is_admin':x.is_admin,'is_active':x.is_active} for x in (await db.execute(select(User).order_by(User.created_at.desc()))).scalars()]
class RefCreate(BaseModel): name:str=Field(min_length=1,max_length=100); category:Optional[str]=None
for path,Model in [('courses',Course),('skills',Skill),('interests',Interest)]:
 async def list_refs(a:User=Depends(admin),db:AsyncSession=Depends(get_db),M=Model): return [{'id':str(x.id),'name':x.name,**({'category':x.category} if hasattr(x,'category') else {})} for x in (await db.execute(select(M).order_by(M.name))).scalars()]
 async def create_ref(b:RefCreate,a:User=Depends(admin),db:AsyncSession=Depends(get_db),M=Model):
  kwargs={'name':b.name.strip()};
  if M is Skill:kwargs['category']=b.category
  x=M(**kwargs);db.add(x);await db.commit();return {'id':str(x.id),'name':x.name}
 app.add_api_route(f'/api/v1/admin/{path}',list_refs,methods=['GET']);app.add_api_route(f'/api/v1/admin/{path}',create_ref,methods=['POST'],status_code=201)
class SocketHub:
 def __init__(self):self.clients={}
 async def add(self,uid,ws):await ws.accept();self.clients.setdefault(uid,set()).add(ws)
 def remove(self,uid,ws):self.clients.get(uid,set()).discard(ws)
 async def send(self,uid,data):
  for ws in list(self.clients.get(uid,set())):
   try:await ws.send_json(data)
   except:self.remove(uid,ws)
hub=SocketHub()
@app.websocket('/api/v1/ws')
async def ws_endpoint(ws:WebSocket):
 token=ws.cookies.get('session')
 if not token:await ws.close(code=4401);return
 from .db import SessionLocal
 async with SessionLocal() as db:
  s=(await db.execute(select(Session).where(Session.token_hash==h(token)))).scalar_one_or_none()
  if not s:await ws.close(code=4401);return
  uid=s.user_id;await hub.add(uid,ws)
  try:
   while True: await ws.receive_text()
  except WebSocketDisconnect:hub.remove(uid,ws)
