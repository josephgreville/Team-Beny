from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    database_url:str='postgresql+asyncpg://cohort:cohort@localhost:5432/cohort'
    frontend_origin:str='http://localhost:5173'
    environment:str='development'
    model_config=SettingsConfigDict(env_file='.env',extra='ignore')
settings=Settings()
