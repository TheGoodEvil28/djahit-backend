from fastapi import FastAPI, File, UploadFile
from ultralytics import YOLO
import cv2
import numpy as np
import base64

app = FastAPI()
model = YOLO("runs/detect/train_pretty_save5/weights/best.pt")
class_names = ["outside_tear","mark","normal","stain","tear","hole"]

@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    img_bytes = await file.read()
    img = cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR)
    results = model(img)

    boxes = []
    for r in results:
        for det in r.boxes.data.cpu().numpy():
            x1, y1, x2, y2, conf, cls = det
            boxes.append({
                "class": class_names[int(cls)],
                "confidence": float(round(conf,3)),
                "bbox": [int(x1), int(y1), int(x2), int(y2)]
            })
    return {"predictions": boxes}
