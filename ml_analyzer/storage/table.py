import peewee

database = peewee.SqliteDatabase(None)


class BaseModel(peewee.Model):
    class Meta:
        database = database


class Apk(BaseModel):
    hash = peewee.TextField(null=False, primary_key=True)
    package = peewee.TextField(null=False)
    file_path = peewee.TextField(null=False)


class ApkFramework(BaseModel):
    apk_hash = peewee.ForeignKeyField(Apk, backref='hash')
    framework = peewee.TextField(null=False)
    evidence_type = peewee.TextField(null=False)
    # TODO: redesign this
    remark = peewee.TextField(null=True)


class Model(BaseModel):
    hash = peewee.TextField(null=False, primary_key=True)
    # path = peewee.TextField(null=False)
    framework = peewee.TextField(null=False)


class ApkModel(BaseModel):
    apk_hash = peewee.ForeignKeyField(Apk, backref='hash')
    model_hash = peewee.ForeignKeyField(Model, backref='hash')
    source_type = peewee.TextField(null=False)
    # TODO: redesign this
    source = peewee.TextField(null=False)
