CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    firstname VARCHAR(50) NOT NULL,
    lastname VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS repair_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_img_url TEXT NOT NULL,
    img_filename VARCHAR(255),
    file_size INTEGER,
    mime_type VARCHAR(100),
    ai_scan_desc TEXT,
    damage_type VARCHAR(50) NOT NULL CHECK (damage_type IN ('Sobek', 'Resleting Rusak', 'Kancing Hilang', 'Lainnya')),
    damage_type_other_desc VARCHAR(500),
    clothing_type VARCHAR(50) NOT NULL CHECK (clothing_type IN ('Baju', 'Celana', 'Outer', 'Lainnya')),
    clothing_type_other_desc VARCHAR(500),
    clothing_size VARCHAR(10) CHECK (clothing_size IN ('XS', 'S', 'M', 'L', 'XL', 'XXL', 'XXXL')),
    pickup_location TEXT NOT NULL,
    pickup_phone VARCHAR(20) NOT NULL,
    thread_color_pref VARCHAR(100),
    estimated_cost DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'Pending' CHECK (status IN ('Pending','Order Diterima','Sedang Dijahit','Dalam Pengiriman','Selesai')),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_repair_requests_user_id ON repair_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_repair_requests_status ON repair_requests(status);
CREATE INDEX IF NOT EXISTS idx_repair_requests_created_at ON repair_requests(created_at);