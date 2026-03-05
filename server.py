from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT and password hashing configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'tu_clave_secreta_super_segura_cambiar_en_produccion')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Create the main app
app = FastAPI(title="Sistema de Supervisión de Visitadores Médicos")

# Create routers
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/auth", tags=["auth"])
visits_router = APIRouter(prefix="/visits", tags=["visits"])
doctors_router = APIRouter(prefix="/doctors", tags=["doctors"])
stats_router = APIRouter(prefix="/stats", tags=["stats"])
users_router = APIRouter(prefix="/users", tags=["users"])

# =================
# Modelos Pydantic
# =================

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    full_name: str
    role: str  # "admin" o "visitador"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    role: str = "visitador"

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class Visit(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    visitador_id: str
    visitador_name: str
    medico_nombre: str
    medico_especialidad: Optional[str] = None
    fecha: datetime
    hora_inicio: datetime
    hora_fin: Optional[datetime] = None
    tiempo_espera_minutos: int = 0
    observaciones: str = ""
    ubicacion_lat: float
    ubicacion_lng: float
    foto_base64: Optional[str] = None
    estado_visita: str = "completa"          # completa | pendiente | reagendada
    checkin_hora: Optional[str] = None       # hora exacta del check-in
    checkin_direccion: Optional[str] = None  # dirección del check-in GPS
    hora_regreso: Optional[str] = None       # hora estimada de regreso (pendiente)
    reagenda_fecha: Optional[str] = None     # fecha nueva (reagendada)
    reagenda_hora: Optional[str] = None      # hora nueva (reagendada)
    synced: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class VisitCreate(BaseModel):
    medico_nombre: str
    medico_especialidad: Optional[str] = None
    fecha: datetime
    hora_inicio: datetime
    hora_fin: Optional[datetime] = None
    tiempo_espera_minutos: int = 0
    observaciones: str = ""
    ubicacion_lat: float
    ubicacion_lng: float
    foto_base64: Optional[str] = None
    estado_visita: str = "completa"          # completa | pendiente | reagendada
    checkin_hora: Optional[str] = None
    checkin_direccion: Optional[str] = None
    hora_regreso: Optional[str] = None
    reagenda_fecha: Optional[str] = None
    reagenda_hora: Optional[str] = None

class VisitUpdate(BaseModel):
    medico_nombre: Optional[str] = None
    medico_especialidad: Optional[str] = None
    hora_fin: Optional[datetime] = None
    tiempo_espera_minutos: Optional[int] = None
    observaciones: Optional[str] = None
    foto_base64: Optional[str] = None
    estado_visita: Optional[str] = None     # completa | pendiente | reagendada
    hora_regreso: Optional[str] = None
    reagenda_fecha: Optional[str] = None
    reagenda_hora: Optional[str] = None

class VisitBatchSync(BaseModel):
    visits: List[VisitCreate]

class Doctor(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nombre: str
    especialidad: str
    ubicacion_lat: Optional[float] = None
    ubicacion_lng: Optional[float] = None
    telefono: Optional[str] = None
    direccion: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DoctorCreate(BaseModel):
    nombre: str
    especialidad: str
    ubicacion_lat: Optional[float] = None
    ubicacion_lng: Optional[float] = None
    telefono: Optional[str] = None
    direccion: Optional[str] = None

class Stats(BaseModel):
    total_visitas: int
    visitas_hoy: int
    visitas_semana: int
    tiempo_espera_promedio: float
    medicos_visitados: int
    visitadores_activos: int

# =================
# Funciones de utilidad
# =================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise credentials_exception
    return User(**user)

async def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="No tiene permisos de administrador")
    return current_user

# =================
# Rutas de Autenticación
# =================

@auth_router.post("/register", response_model=User)
async def register(user_data: UserCreate):
    # Verificar si el usuario ya existe
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    
    # Crear nuevo usuario
    hashed_password = get_password_hash(user_data.password)
    user_dict = user_data.dict()
    user_dict.pop('password')
    user_obj = User(**user_dict)
    
    user_in_db = UserInDB(**user_obj.dict(), hashed_password=hashed_password)
    await db.users.insert_one(user_in_db.dict())
    
    return user_obj

@auth_router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_in_db = UserInDB(**user)
    if not verify_password(form_data.password, user_in_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user_in_db.is_active:
        raise HTTPException(status_code=400, detail="Usuario inactivo")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_in_db.id}, expires_delta=access_token_expires
    )
    
    user_obj = User(**{k: v for k, v in user_in_db.dict().items() if k != 'hashed_password'})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=user_obj
    )

@auth_router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# =================
# Rutas de Usuarios (Admin)
# =================

class PasswordChange(BaseModel):
    new_password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None

@users_router.get("/", response_model=List[User])
async def get_all_users(current_user: User = Depends(get_current_admin)):
    """Obtener todos los usuarios (solo admin)"""
    users = await db.users.find().to_list(100)
    return [User(**{k: v for k, v in u.items() if k != 'hashed_password'}) for u in users]

@users_router.post("/", response_model=User)
async def create_user(user_data: UserCreate, current_user: User = Depends(get_current_admin)):
    """Crear nuevo usuario (solo admin)"""
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    
    hashed_password = get_password_hash(user_data.password)
    user_dict = user_data.dict()
    user_dict.pop('password')
    user_obj = User(**user_dict)
    
    user_in_db = UserInDB(**user_obj.dict(), hashed_password=hashed_password)
    await db.users.insert_one(user_in_db.dict())
    
    return user_obj

@users_router.put("/{user_id}/password")
async def change_user_password(
    user_id: str, 
    password_data: PasswordChange, 
    current_user: User = Depends(get_current_admin)
):
    """Cambiar contraseña de un usuario (solo admin)"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    new_hash = get_password_hash(password_data.new_password)
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"hashed_password": new_hash}}
    )
    
    return {"message": f"Contraseña actualizada para {user['username']}"}

@users_router.put("/{user_id}")
async def update_user(
    user_id: str, 
    user_data: UserUpdate, 
    current_user: User = Depends(get_current_admin)
):
    """Actualizar datos de usuario (solo admin)"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    update_data = {k: v for k, v in user_data.dict().items() if v is not None}
    if update_data:
        await db.users.update_one({"id": user_id}, {"$set": update_data})
    
    updated_user = await db.users.find_one({"id": user_id})
    return User(**{k: v for k, v in updated_user.items() if k != 'hashed_password'})

@users_router.delete("/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(get_current_admin)):
    """Eliminar usuario (solo admin)"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    if user['role'] == 'admin':
        raise HTTPException(status_code=400, detail="No se puede eliminar al administrador")
    
    await db.users.delete_one({"id": user_id})
    return {"message": f"Usuario {user['username']} eliminado"}

# =================
# Rutas de Visitas
# =================

@visits_router.post("/", response_model=Visit)
async def create_visit(visit_data: VisitCreate, current_user: User = Depends(get_current_user)):
    visit_dict = visit_data.dict()
    visit_dict['visitador_id'] = current_user.id
    visit_dict['visitador_name'] = current_user.full_name
    visit_dict['synced'] = True
    
    visit_obj = Visit(**visit_dict)
    await db.visits.insert_one(visit_obj.dict())
    
    return visit_obj

@visits_router.post("/batch-sync")
async def batch_sync_visits(batch: VisitBatchSync, current_user: User = Depends(get_current_user)):
    visits_to_insert = []
    for visit_data in batch.visits:
        visit_dict = visit_data.dict()
        visit_dict['visitador_id'] = current_user.id
        visit_dict['visitador_name'] = current_user.full_name
        visit_dict['synced'] = True
        visit_obj = Visit(**visit_dict)
        visits_to_insert.append(visit_obj.dict())
    
    if visits_to_insert:
        await db.visits.insert_many(visits_to_insert)
    
    return {"status": "success", "synced_count": len(visits_to_insert)}

@visits_router.get("/", response_model=List[Visit])
async def get_visits(
    visitador_id: Optional[str] = None,
    fecha_desde: Optional[datetime] = None,
    fecha_hasta: Optional[datetime] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    query = {}
    
    # Si no es admin, solo puede ver sus propias visitas
    if current_user.role != "admin":
        query['visitador_id'] = current_user.id
    elif visitador_id:
        query['visitador_id'] = visitador_id
    
    if fecha_desde:
        query['fecha'] = {"$gte": fecha_desde}
    if fecha_hasta:
        if 'fecha' in query:
            query['fecha']['$lte'] = fecha_hasta
        else:
            query['fecha'] = {"$lte": fecha_hasta}
    
    visits = await db.visits.find(query).sort("fecha", -1).limit(limit).to_list(limit)
    return [Visit(**visit) for visit in visits]

@visits_router.get("/{visit_id}", response_model=Visit)
async def get_visit(visit_id: str, current_user: User = Depends(get_current_user)):
    visit = await db.visits.find_one({"id": visit_id})
    if not visit:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    
    # Si no es admin, solo puede ver sus propias visitas
    if current_user.role != "admin" and visit['visitador_id'] != current_user.id:
        raise HTTPException(status_code=403, detail="No tiene permisos para ver esta visita")
    
    return Visit(**visit)

@visits_router.put("/{visit_id}", response_model=Visit)
async def update_visit(visit_id: str, visit_update: VisitUpdate, current_user: User = Depends(get_current_user)):
    visit = await db.visits.find_one({"id": visit_id})
    if not visit:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    
    # Solo el visitador dueño o admin puede actualizar
    if visit['visitador_id'] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="No tiene permisos para actualizar esta visita")
    
    update_data = visit_update.dict(exclude_unset=True)
    if update_data:
        await db.visits.update_one({"id": visit_id}, {"$set": update_data})
    
    updated_visit = await db.visits.find_one({"id": visit_id})
    return Visit(**updated_visit)

@visits_router.patch("/{visit_id}", response_model=Visit)
async def patch_visit(visit_id: str, visit_update: VisitUpdate, current_user: User = Depends(get_current_user)):
    """Actualización parcial de visita: estado, observaciones y acotaciones."""
    visit = await db.visits.find_one({"id": visit_id})
    if not visit:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    
    # Solo el visitador dueño o admin puede editar
    if visit['visitador_id'] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="No tiene permisos para editar esta visita")
    
    # Validar estado si viene en el payload
    update_data = visit_update.dict(exclude_unset=True)
    if "estado_visita" in update_data:
        estados_validos = {"completa", "pendiente", "reagendada"}
        if update_data["estado_visita"] not in estados_validos:
            raise HTTPException(status_code=400, detail=f"Estado inválido. Usa: {estados_validos}")
    
    if update_data:
        await db.visits.update_one({"id": visit_id}, {"$set": update_data})
    
    updated_visit = await db.visits.find_one({"id": visit_id})
    return Visit(**updated_visit)

@visits_router.delete("/{visit_id}")
async def delete_visit(visit_id: str, current_user: User = Depends(get_current_admin)):
    result = await db.visits.delete_one({"id": visit_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Visita no encontrada")
    return {"status": "deleted"}

# =================
# Rutas de Médicos
# =================

@doctors_router.post("/", response_model=Doctor)
async def create_doctor(doctor_data: DoctorCreate, current_user: User = Depends(get_current_user)):
    doctor_obj = Doctor(**doctor_data.dict())
    await db.doctors.insert_one(doctor_obj.dict())
    return doctor_obj

@doctors_router.get("/", response_model=List[Doctor])
async def get_doctors(limit: int = 100, current_user: User = Depends(get_current_user)):
    doctors = await db.doctors.find().limit(limit).to_list(limit)
    return [Doctor(**doctor) for doctor in doctors]

@doctors_router.get("/{doctor_id}", response_model=Doctor)
async def get_doctor(doctor_id: str, current_user: User = Depends(get_current_user)):
    doctor = await db.doctors.find_one({"id": doctor_id})
    if not doctor:
        raise HTTPException(status_code=404, detail="Médico no encontrado")
    return Doctor(**doctor)

# =================
# Rutas de Estadísticas
# =================

@stats_router.get("/", response_model=Stats)
async def get_stats(current_user: User = Depends(get_current_admin)):
    # Total de visitas
    total_visitas = await db.visits.count_documents({})
    
    # Visitas de hoy
    hoy_inicio = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    hoy_fin = hoy_inicio + timedelta(days=1)
    visitas_hoy = await db.visits.count_documents({
        "fecha": {"$gte": hoy_inicio, "$lt": hoy_fin}
    })
    
    # Visitas de la semana
    semana_inicio = hoy_inicio - timedelta(days=hoy_inicio.weekday())
    visitas_semana = await db.visits.count_documents({
        "fecha": {"$gte": semana_inicio}
    })
    
    # Tiempo de espera promedio
    pipeline = [
        {"$group": {"_id": None, "avg_tiempo": {"$avg": "$tiempo_espera_minutos"}}}
    ]
    result = await db.visits.aggregate(pipeline).to_list(1)
    tiempo_espera_promedio = result[0]['avg_tiempo'] if result and result[0]['avg_tiempo'] else 0
    
    # Médicos únicos visitados
    medicos_visitados = len(await db.visits.distinct("medico_nombre"))
    
    # Visitadores activos
    visitadores_activos = await db.users.count_documents({"role": "visitador", "is_active": True})
    
    return Stats(
        total_visitas=total_visitas,
        visitas_hoy=visitas_hoy,
        visitas_semana=visitas_semana,
        tiempo_espera_promedio=round(tiempo_espera_promedio, 2),
        medicos_visitados=medicos_visitados,
        visitadores_activos=visitadores_activos
    )

@stats_router.get("/medicos-mas-visitados")
async def get_top_doctors(limit: int = 10, current_user: User = Depends(get_current_admin)):
    pipeline = [
        {"$group": {
            "_id": "$medico_nombre",
            "total_visitas": {"$sum": 1},
            "especialidad": {"$first": "$medico_especialidad"}
        }},
        {"$sort": {"total_visitas": -1}},
        {"$limit": limit}
    ]
    
    result = await db.visits.aggregate(pipeline).to_list(limit)
    return [
        {
            "medico": doc['_id'],
            "especialidad": doc['especialidad'],
            "total_visitas": doc['total_visitas']
        }
        for doc in result
    ]

@stats_router.get("/visitas-por-dia")
async def get_visits_per_day(dias: int = 7, current_user: User = Depends(get_current_admin)):
    fecha_inicio = datetime.utcnow() - timedelta(days=dias)
    
    pipeline = [
        {"$match": {"fecha": {"$gte": fecha_inicio}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$fecha"}},
            "total": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    
    result = await db.visits.aggregate(pipeline).to_list(dias)
    return [
        {"fecha": doc['_id'], "total": doc['total']}
        for doc in result
    ]

@stats_router.get("/rutas-visitador/{visitador_id}")
async def get_visitador_routes(
    visitador_id: str,
    fecha: Optional[datetime] = None,
    current_user: User = Depends(get_current_admin)
):
    query = {"visitador_id": visitador_id}
    
    if fecha:
        fecha_inicio = fecha.replace(hour=0, minute=0, second=0, microsecond=0)
        fecha_fin = fecha_inicio + timedelta(days=1)
        query['fecha'] = {"$gte": fecha_inicio, "$lt": fecha_fin}
    
    visits = await db.visits.find(query).sort("hora_inicio", 1).to_list(100)
    
    rutas = [
        {
            "id": visit['id'],
            "medico": visit['medico_nombre'],
            "hora": visit['hora_inicio'],
            "ubicacion": {
                "lat": visit['ubicacion_lat'],
                "lng": visit['ubicacion_lng']
            },
            "tiempo_espera": visit['tiempo_espera_minutos']
        }
        for visit in visits
    ]
    
    return rutas

# =================
# Rutas de Usuarios (Admin)
# =================

@users_router.get("/", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_admin)):
    users = await db.users.find().to_list(100)
    return [User(**{k: v for k, v in user.items() if k != 'hashed_password'}) for user in users]

@users_router.get("/{user_id}", response_model=User)
async def get_user(user_id: str, current_user: User = Depends(get_current_admin)):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return User(**{k: v for k, v in user.items() if k != 'hashed_password'})

# =================
# Incluir routers
# =================

api_router.include_router(auth_router)
api_router.include_router(visits_router)
api_router.include_router(doctors_router)
api_router.include_router(stats_router)
api_router.include_router(users_router)

app.include_router(api_router)

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_db():
    # Crear usuario admin por defecto si no existe
    admin_exists = await db.users.find_one({"username": "admin"})
    if not admin_exists:
        admin_user = UserInDB(
            id=str(uuid.uuid4()),
            username="admin",
            full_name="Administrador",
            role="admin",
            hashed_password=get_password_hash("admin123"),
            is_active=True,
            created_at=datetime.utcnow()
        )
        await db.users.insert_one(admin_user.dict())
        logger.info("Usuario admin creado: username=admin, password=admin123")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
