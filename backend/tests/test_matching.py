from types import SimpleNamespace
from app.main import score
def p(role,skills=(),interests=(),course='x'):
 return SimpleNamespace(profile=SimpleNamespace(role=role,skills=[SimpleNamespace(name=x) for x in skills],interests=[SimpleNamespace(name=x) for x in interests],course_id=course))
def test_score_caps_and_complementary_role():
 a=p('software_developer',['Python','SQL','React','JS'],['AI','Fintech','Climate','Games'])
 b=p('business_developer',['Python','SQL','React','JS'],['AI','Fintech','Climate','Games'])
 score_value,_=score(a,b); assert score_value==95
