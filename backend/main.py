from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Set
from datetime import datetime, timedelta
import jwt as pyjwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import json
import uuid
from pathlib import Path

from database import get_db, init_db, User, Room, Post, Comment, Message, Like, RoomMessage, SessionLocal

app = FastAPI(
    title="Talk API",
    description="Backend para aplicación de chat social con SQLite",
    version="2.0.0"
)

# Configuración de seguridad
SECRET_KEY = "talk_secret_key_2025_super_segura_produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()

# Crear carpeta para uploads
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== WEBSOCKET MANAGER ====================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, room_id: int):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = set()
        self.active_connections[room_id].add(websocket)
    
    def disconnect(self, websocket: WebSocket, room_id: int):
        if room_id in self.active_connections:
            self.active_connections[room_id].discard(websocket)
    
    async def broadcast(self, message: dict, room_id: int):
        if room_id in self.active_connections:
            for connection in self.active_connections[room_id]:
                try:
                    await connection.send_json(message)
                except:
                    pass

manager = ConnectionManager()

# ==================== MODELOS PYDANTIC ====================

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    avatar: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class RoomCreate(BaseModel):
    name: str
    description: Optional[str] = None
    emoji: str = "💬"
    is_private: bool = False

class RoomResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    emoji: str
    members: int = 0
    created_by: int
    created_at: datetime
    is_private: bool

    class Config:
        from_attributes = True

class PostCreate(BaseModel):
    content: str
    room_id: int

class PostUpdate(BaseModel):
    content: str

class PostResponse(BaseModel):
    id: int
    content: str
    user_id: int
    username: str
    user_avatar: str
    room_id: int
    room_name: str
    likes: int
    comments: int
    created_at: datetime

class CommentCreate(BaseModel):
    content: str
    post_id: int

class CommentResponse(BaseModel):
    id: int
    content: str
    user_id: int
    username: str
    post_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class MessageCreate(BaseModel):
    content: str
    receiver_id: int

class MessageResponse(BaseModel):
    id: int
    content: str
    sender_id: int
    sender_username: str
    receiver_id: int
    receiver_username: str
    created_at: datetime
    read: bool

class UserUpdateProfile(BaseModel):
    full_name: Optional[str] = None
    avatar: Optional[str] = None

class RoomMessageCreate(BaseModel):
    content: Optional[str] = None
    message_type: str = "text"
    room_id: int

class RoomMessageResponse(BaseModel):
    id: int
    content: Optional[str]
    message_type: str
    file_url: Optional[str]
    sender_id: int
    sender_username: str
    sender_avatar: str
    room_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# ==================== FUNCIONES DE UTILIDAD ====================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except pyjwt.JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return user

# ==================== EVENTO DE INICIO ====================

@app.on_event("startup")
async def startup_event():
    init_db()
    db = SessionLocal()
    
    # Crear solo la sala General si no existe
    if db.query(Room).count() == 0:
        default_room = Room(
            name="General", 
            description="Sala principal de conversación", 
            emoji="💬", 
            created_by=1
        )
        db.add(default_room)
        db.commit()
        print("✅ Sala General creada")
    
    db.close()
# ==================== ENDPOINTS DE AUTENTICACIÓN ====================

@app.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="El username ya está registrado")
    
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    
    new_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        password=get_password_hash(user.password),
        avatar=user.username[0].upper()
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token = create_access_token(data={"sub": user.username})
    user_response = UserResponse.from_orm(new_user)
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.post("/login", response_model=Token)
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    user_response = UserResponse.from_orm(db_user)
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)

@app.put("/users/me/update", response_model=UserResponse)
async def update_profile(
    profile_data: UserUpdateProfile,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if profile_data.full_name is not None:
        current_user.full_name = profile_data.full_name
    
    if profile_data.avatar is not None:
        if profile_data.avatar.startswith('data:image'):
            current_user.avatar = profile_data.avatar[:100]
        else:
            current_user.avatar = profile_data.avatar
    
    db.commit()
    db.refresh(current_user)
    
    return UserResponse.from_orm(current_user)

# ==================== ENDPOINTS DE SALAS ====================
@app.get("/rooms", response_model=List[RoomResponse])
async def get_rooms(db: Session = Depends(get_db)):
    rooms = db.query(Room).all()
    
    result = []
    for room in rooms:
        members_count = len(room.members)
        
        result.append(RoomResponse(
            id=room.id,
            name=room.name,
            description=room.description,
            emoji=room.emoji,
            members=members_count,  # Contar miembros correctamente
            created_by=room.created_by,
            created_at=room.created_at,
            is_private=room.is_private
        ))
    
    return result

@app.get("/rooms/{room_id}", response_model=RoomResponse)
async def get_room(room_id: int, db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    # Contar miembros en lugar de pasar la lista
    members_count = len(room.members)
    
    # Crear respuesta manualmente
    return RoomResponse(
        id=room.id,
        name=room.name,
        description=room.description,
        emoji=room.emoji,
        members=members_count,  # Pasar el conteo como entero
        created_by=room.created_by,
        created_at=room.created_at,
        is_private=room.is_private
    )

@app.post("/rooms", response_model=RoomResponse, status_code=status.HTTP_201_CREATED)
async def create_room(
    room: RoomCreate, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_room = Room(
        name=room.name,
        description=room.description,
        emoji=room.emoji,
        is_private=room.is_private,
        created_by=current_user.id
    )
    
    db.add(new_room)
    db.commit()
    db.refresh(new_room)
    
    # Agregar al creador como miembro
    new_room.members.append(current_user)
    db.commit()
    
    # Crear respuesta con el conteo de miembros
    return RoomResponse(
        id=new_room.id,
        name=new_room.name,
        description=new_room.description,
        emoji=new_room.emoji,
        members=len(new_room.members),  # Contar los miembros
        created_by=new_room.created_by,
        created_at=new_room.created_at,
        is_private=new_room.is_private
    )

@app.post("/rooms/{room_id}/join")
async def join_room(
    room_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    if current_user in room.members:
        return {"message": "Ya eres miembro de esta sala"}
    
    room.members.append(current_user)
    db.commit()
    
    await manager.broadcast({
        "type": "user_joined",
        "username": current_user.username,
        "user_id": current_user.id,
        "avatar": current_user.avatar,
        "message": f"{current_user.username} se unió a la sala"
    }, room_id)
    
    return {"message": "Te has unido a la sala exitosamente"}

@app.post("/rooms/{room_id}/leave")
async def leave_room(
    room_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    if current_user in room.members:
        room.members.remove(current_user)
        db.commit()
        
        await manager.broadcast({
            "type": "user_left",
            "username": current_user.username,
            "message": f"{current_user.username} salió de la sala"
        }, room_id)
    
    return {"message": "Has salido de la sala"}

@app.get("/rooms/{room_id}/members")
async def get_room_members(
    room_id: int,
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    return [
        {
            "id": member.id,
            "username": member.username,
            "avatar": member.avatar,
            "full_name": member.full_name
        }
        for member in room.members
    ]

# ==================== ENDPOINTS DE MENSAJES DE SALA ====================

@app.get("/rooms/{room_id}/messages", response_model=List[RoomMessageResponse])
async def get_room_messages(
    room_id: int,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    messages = db.query(RoomMessage).filter(
        RoomMessage.room_id == room_id
    ).order_by(RoomMessage.created_at.desc()).limit(limit).all()
    
    result = []
    for msg in reversed(messages):
        result.append(RoomMessageResponse(
            id=msg.id,
            content=msg.content,
            message_type=msg.message_type,
            file_url=msg.file_url,
            sender_id=msg.sender_id,
            sender_username=msg.sender.username,
            sender_avatar=msg.sender.avatar,
            room_id=msg.room_id,
            created_at=msg.created_at
        ))
    
    return result

@app.post("/rooms/{room_id}/messages")
async def send_room_message(
    room_id: int,
    message: RoomMessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    new_message = RoomMessage(
        content=message.content,
        message_type=message.message_type,
        sender_id=current_user.id,
        room_id=room_id
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    await manager.broadcast({
        "type": "new_message",
        "id": new_message.id,
        "content": new_message.content,
        "message_type": new_message.message_type,
        "file_url": new_message.file_url,
        "sender_id": current_user.id,
        "sender_username": current_user.username,
        "sender_avatar": current_user.avatar,
        "created_at": new_message.created_at.isoformat()
    }, room_id)
    
    return {"message": "Mensaje enviado", "id": new_message.id}

@app.post("/rooms/{room_id}/upload")
async def upload_file(
    room_id: int,
    file: UploadFile = File(...),
    message_type: str = "image",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    # Validar tipo de archivo
    allowed_extensions = {
        "image": ["jpg", "jpeg", "png", "gif", "webp"],
        "video": ["mp4", "webm", "mov"],
        "audio": ["mp3", "wav", "ogg", "m4a"]
    }
    
    file_extension = file.filename.split(".")[-1].lower()
    if file_extension not in allowed_extensions.get(message_type, []):
        raise HTTPException(status_code=400, detail="Tipo de archivo no permitido")
    
    # Generar nombre único
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    file_path = UPLOAD_DIR / unique_filename
    
    # Guardar archivo
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    file_url = f"/uploads/{unique_filename}"
    
    # Crear mensaje
    content_text = {
        "image": "📷 Compartió una imagen",
        "video": "🎥 Compartió un video",
        "audio": "🎵 Compartió un audio"
    }.get(message_type, "📎 Compartió un archivo")
    
    new_message = RoomMessage(
        content=content_text,
        message_type=message_type,
        file_url=file_url,
        sender_id=current_user.id,
        room_id=room_id
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    await manager.broadcast({
        "type": "new_message",
        "id": new_message.id,
        "content": new_message.content,
        "message_type": new_message.message_type,
        "file_url": new_message.file_url,
        "sender_id": current_user.id,
        "sender_username": current_user.username,
        "sender_avatar": current_user.avatar,
        "created_at": new_message.created_at.isoformat()
    }, room_id)
    
    return {"message": "Archivo subido", "file_url": file_url, "id": new_message.id}

# ==================== WEBSOCKET ====================

@app.websocket("/ws/room/{room_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    room_id: int,
    token: str,
    db: Session = Depends(get_db)
):
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            await websocket.close(code=1008)
            return
        
        await manager.connect(websocket, room_id)
        
        await manager.broadcast({
            "type": "user_connected",
            "username": user.username,
            "user_id": user.id,
            "avatar": user.avatar
        }, room_id)
        
        try:
            while True:
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                if message_data.get("type") == "message":
                    new_message = RoomMessage(
                        content=message_data.get("content"),
                        message_type="text",
                        sender_id=user.id,
                        room_id=room_id
                    )
                    db.add(new_message)
                    db.commit()
                    db.refresh(new_message)
                    
                    await manager.broadcast({
                        "type": "new_message",
                        "id": new_message.id,
                        "content": new_message.content,
                        "message_type": "text",
                        "sender_id": user.id,
                        "sender_username": user.username,
                        "sender_avatar": user.avatar,
                        "created_at": new_message.created_at.isoformat()
                    }, room_id)
                
                elif message_data.get("type") == "typing":
                    await manager.broadcast({
                        "type": "typing",
                        "username": user.username,
                        "is_typing": message_data.get("is_typing", False)
                    }, room_id)
        
        except WebSocketDisconnect:
            manager.disconnect(websocket, room_id)
            await manager.broadcast({
                "type": "user_disconnected",
                "username": user.username
            }, room_id)
    
    except Exception as e:
        print(f"WebSocket error: {e}")
        await websocket.close(code=1011)

# ==================== ENDPOINTS DE PUBLICACIONES ====================

@app.get("/posts", response_model=List[PostResponse])
async def get_posts(room_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(Post)
    
    if room_id:
        query = query.filter(Post.room_id == room_id)
    
    posts = query.order_by(Post.created_at.desc()).all()
    
    result = []
    for post in posts:
        comments_count = db.query(Comment).filter(Comment.post_id == post.id).count()
        
        result.append(PostResponse(
            id=post.id,
            content=post.content,
            user_id=post.user_id,
            username=post.author.username,
            user_avatar=post.author.avatar,
            room_id=post.room_id,
            room_name=post.room.name,
            likes=post.likes,
            comments=comments_count,
            created_at=post.created_at
        ))
    
    return result

@app.get("/posts/{post_id}", response_model=PostResponse)
async def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Publicación no encontrada")
    
    comments_count = db.query(Comment).filter(Comment.post_id == post.id).count()
    
    return PostResponse(
        id=post.id,
        content=post.content,
        user_id=post.user_id,
        username=post.author.username,
        user_avatar=post.author.avatar,
        room_id=post.room_id,
        room_name=post.room.name,
        likes=post.likes,
        comments=comments_count,
        created_at=post.created_at
    )

@app.post("/posts", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
async def create_post(
    post: PostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    room = db.query(Room).filter(Room.id == post.room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Sala no encontrada")
    
    new_post = Post(
        content=post.content,
        user_id=current_user.id,
        room_id=post.room_id
    )
    
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    
    return PostResponse(
        id=new_post.id,
        content=new_post.content,
        user_id=new_post.user_id,
        username=current_user.username,
        user_avatar=current_user.avatar,
        room_id=new_post.room_id,
        room_name=room.name,
        likes=0,
        comments=0,
        created_at=new_post.created_at
    )

@app.put("/posts/{post_id}", response_model=PostResponse)
async def update_post(
    post_id: int,
    post_data: PostUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(status_code=404, detail="Publicación no encontrada")
    
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar esta publicación")
    
    post.content = post_data.content
    db.commit()
    db.refresh(post)
    
    comments_count = db.query(Comment).filter(Comment.post_id == post.id).count()
    
    return PostResponse(
        id=post.id,
        content=post.content,
        user_id=post.user_id,
        username=post.author.username,
        user_avatar=post.author.avatar,
        room_id=post.room_id,
        room_name=post.room.name,
        likes=post.likes,
        comments=comments_count,
        created_at=post.created_at
    )

@app.delete("/posts/{post_id}")
async def delete_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(status_code=404, detail="Publicación no encontrada")
    
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para eliminar esta publicación")
    
    db.query(Comment).filter(Comment.post_id == post_id).delete()
    db.query(Like).filter(Like.post_id == post_id).delete()
    db.delete(post)
    db.commit()
    
    return {"message": "Publicación eliminada exitosamente"}

# ==================== ENDPOINTS DE LIKES ====================

@app.post("/posts/{post_id}/like")
async def toggle_like(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Publicación no encontrada")
    
    existing_like = db.query(Like).filter(
        Like.user_id == current_user.id,
        Like.post_id == post_id
    ).first()
    
    if existing_like:
        db.delete(existing_like)
        post.likes = max(0, post.likes - 1)
        db.commit()
        return {"message": "Like removido", "likes": post.likes, "liked": False}
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.add(new_like)
        post.likes += 1
        db.commit()
        return {"message": "Like agregado", "likes": post.likes, "liked": True}

# ==================== ENDPOINTS DE COMENTARIOS ====================

@app.get("/posts/{post_id}/comments", response_model=List[CommentResponse])
async def get_comments(post_id: int, db: Session = Depends(get_db)):
    comments = db.query(Comment).filter(Comment.post_id == post_id).order_by(Comment.created_at).all()
    
    result = []
    for comment in comments:
        result.append(CommentResponse(
            id=comment.id,
            content=comment.content,
            user_id=comment.user_id,
            username=comment.author.username,
            post_id=comment.post_id,
            created_at=comment.created_at
        ))
    
    return result

@app.post("/comments", response_model=CommentResponse, status_code=status.HTTP_201_CREATED)
async def create_comment(
    comment: CommentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == comment.post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Publicación no encontrada")
    
    new_comment = Comment(
        content=comment.content,
        user_id=current_user.id,
        post_id=comment.post_id
    )
    
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    
    return CommentResponse(
        id=new_comment.id,
        content=new_comment.content,
        user_id=new_comment.user_id,
        username=current_user.username,
        post_id=new_comment.post_id,
        created_at=new_comment.created_at
    )

@app.put("/comments/{comment_id}")
async def update_comment(
    comment_id: int,
    content: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    
    if not comment:
        raise HTTPException(status_code=404, detail="Comentario no encontrado")
    
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para editar este comentario")
    
    comment.content = content
    db.commit()
    db.refresh(comment)
    
    return CommentResponse(
        id=comment.id,
        content=comment.content,
        user_id=comment.user_id,
        username=comment.author.username,
        post_id=comment.post_id,
        created_at=comment.created_at
    )

@app.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    
    if not comment:
        raise HTTPException(status_code=404, detail="Comentario no encontrado")
    
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para eliminar este comentario")
    
    db.delete(comment)
    db.commit()
    
    return {"message": "Comentario eliminado exitosamente"}

# ==================== ENDPOINTS DE MENSAJES DIRECTOS ====================

@app.get("/messages", response_model=List[MessageResponse])
async def get_messages(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    messages = db.query(Message).filter(
        (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
    ).order_by(Message.created_at.desc()).all()
    
    result = []
    for msg in messages:
        result.append(MessageResponse(
            id=msg.id,
            content=msg.content,
            sender_id=msg.sender_id,
            sender_username=msg.sender.username,
            receiver_id=msg.receiver_id,
            receiver_username=msg.receiver.username,
            created_at=msg.created_at,
            read=msg.read
        ))
    
    return result

@app.get("/search/users")
async def search_users(q: str, db: Session = Depends(get_db)):
    users = db.query(User).filter(
        (User.username.contains(q)) | (User.full_name.contains(q))
    ).limit(10).all()
    
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "avatar": u.avatar
        }
        for u in users
    ]

# ==================== ENDPOINTS PRINCIPALES ====================

@app.get("/")
async def root():
    return {
        "message": "Talk API con SQLite - Backend funcionando correctamente",
        "version": "2.0.0",
        "database": "SQLite",
        "encryption": "Argon2",
        "websocket": "Enabled",
        "docs": "/docs",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    return {
        "status": "OK",
        "users": db.query(User).count(),
        "rooms": db.query(Room).count(),
        "posts": db.query(Post).count(),
        "messages": db.query(Message).count(),
        "room_messages": db.query(RoomMessage).count(),
        "database": "SQLite",
        "timestamp": datetime.now().isoformat()
    }