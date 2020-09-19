from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
import config as cfg

database_default_path = cfg.database["path"]
engine = create_engine('sqlite:///' + str(os.getenv('VULNERABILITY_DATABASE_PATH', database_default_path)), convert_unicode=True, echo=False)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    # import all modules here that might define models so that
    Base.metadata.create_all(bind=engine)
