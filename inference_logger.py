from ultralytics import YOLO
import os
import json

os.environ['KMP_DUPLICATE_LIB_OK']='True'
log_dump_path = './detections_logs.json'

class InferenceLogger:

    def __init__(self, modelPath) -> None:
        self.model = YOLO(modelPath)
        self.results_arr = []
    
    def display_model(self):
        print(self.model)
    
    def log_detection_results(self, img_path, detections):
        for detection in detections:
            if len(detection) > 0:
                class_num = detection[0].boxes.cls.squeeze().item()
                self.results_arr.append({
                    'image': img_path,
                    'class_num': class_num,
                    'confidence': detection[0].boxes.conf.squeeze().item(),
                    'class': detection[0].names[class_num]
                })
    
    def detect(self, dir):
        for filename in os.listdir(dir):
            file_path = os.path.join(dir, filename)
            if os.path.isfile(file_path):
                detections = self.model.predict(file_path)
                self.log_detection_results(file_path, detections)

        with open(log_dump_path, 'w') as file:
            json.dump(self.results_arr, file)
        
        print('############################')
        print('   DETECTION LOG WRITTEN    ')
        print('############################')
        return
