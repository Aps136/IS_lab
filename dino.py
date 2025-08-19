# !pip install timm
# !pip install pytorch-grad-cam opencv-python matplotlib
# !pip install scikit-learn
# !pip install timm

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, ConcatDataset, Subset
from torchvision import transforms, datasets
from tqdm import tqdm
import os
import matplotlib.pyplot as plt
import numpy as np
import cv2
from collections import Counter
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import StratifiedKFold
import timm

# Grad-CAM specific imports
from pytorch_grad_cam import GradCAM
from pytorch_grad_cam.utils.model_targets import ClassifierOutputTarget
from pytorch_grad_cam.utils.image import show_cam_on_image

# ==============================================================================
# === KEY CONFIGURATION SECTION ================================================
# ==============================================================================

# --- 1. Define Essential Variables and Setup ---
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

# --- Model and Data Parameters ---
dino_backbone_dim = 768    # Dimension of the DINOv2 backbone's output features (ViT-B/16 typically)
num_classes = 2          # Set to the number of classes in your dataset (e.g., 2 for benign/malignant)

# --- Training Parameters ---
NUM_FOLDS = 5              # Changed to 5 as requested.
EPOCHS = 300               # Changed to 300 as requested.
PATIENCE = 10              # Number of epochs to wait for improvement before early stopping.
BATCH_SIZE = 32
NUM_WORKERS = os.cpu_count() // 2 if os.cpu_count() else 2

# --- File Paths ---
DATA_ROOT_PATH = "/home/swathi/Aparna/newds"
classifier_save_dir = "saved_classifiers_breast_cancer"
os.makedirs(classifier_save_dir, exist_ok=True)
print(f"Classifier save directory: {os.path.abspath(classifier_save_dir)}")

# Lists to store per-fold metrics for plotting
plot_fold_train_losses = []
plot_fold_val_losses = []
plot_fold_train_accuracies = []
plot_fold_val_accuracies = []

# Lists to store final metrics for summary
all_fold_best_acc = []
all_fold_best_loss = []
fold_val_precision = []
fold_val_recall = []
fold_val_f1 = []


# --- 2. Define Transforms ---
train_transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.RandomHorizontalFlip(),
    transforms.RandomVerticalFlip(),
    transforms.RandomRotation(45),
    transforms.ColorJitter(brightness=0.3, contrast=0.3, saturation=0.3, hue=0.15),
    transforms.RandomGrayscale(p=0.1),
    transforms.RandomPerspective(distortion_scale=0.2, p=0.5),
    transforms.RandomAffine(degrees=15, translate=(0.1, 0.1), scale=(0.9, 1.1), shear=10),
    transforms.ToTensor(),
    transforms.Normalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225)),
    transforms.RandomErasing(p=0.2, scale=(0.02, 0.1), ratio=(0.3, 3.3), value='random')
])

val_transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=(0.485, 0.456, 0.406), std=(0.229, 0.224, 0.225)),
])

# Function to denormalize image for visualization
def denormalize_image(tensor):
    mean = torch.tensor([0.485, 0.456, 0.406], dtype=torch.float32, device=tensor.device).view(3, 1, 1)
    std = torch.tensor([0.229, 0.224, 0.225], dtype=torch.float32, device=tensor.device).view(3, 1, 1)
    denormalized_tensor = tensor * std + mean
    denormalized_tensor = torch.clamp(denormalized_tensor, 0, 1)
    return denormalized_tensor

# Class to handle transforms per fold to prevent data leakage
class DatasetWithTransform(Subset):
    def __init__(self, dataset, indices, transform=None):
        super().__init__(dataset, indices)
        self.transform = transform
        
    def __getitem__(self, idx):
        original_idx = self.indices[idx]
        image, label = self.dataset[original_idx]
        if self.transform:
            image = self.transform(image)
        return image, label

# --- 3. Load Datasets for K-Fold ---
train_dir = os.path.join(DATA_ROOT_PATH, 'train')
val_dir = os.path.join(DATA_ROOT_PATH, 'val')
test_dir = os.path.join(DATA_ROOT_PATH, 'test')

if not os.path.exists(train_dir) or not os.path.exists(val_dir):
    raise FileNotFoundError(f"ERROR: Missing 'train' or 'val' directory at {DATA_ROOT_PATH}. Please check the DATA_ROOT_PATH variable.")

combined_dataset_raw = ConcatDataset([
    datasets.ImageFolder(root=train_dir, transform=transforms.ToTensor()),
    datasets.ImageFolder(root=val_dir, transform=transforms.ToTensor())
])
all_targets = [sample[1] for sample in combined_dataset_raw]

test_dataset = None
test_loader = None
if os.path.exists(test_dir):
    test_dataset = datasets.ImageFolder(root=test_dir, transform=val_transform)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=NUM_WORKERS)
    target_class_names = test_dataset.classes
else:
    target_class_names = combined_dataset_raw.datasets[0].classes
    print(f"Warning: Test directory not found at {test_dir}. Skipping test set evaluation and Grad-CAM visualization.")

if len(combined_dataset_raw) == 0:
    raise ValueError("ERROR: The combined dataset is empty. Please check your data folders for images.")

print(f"Detected classes: {combined_dataset_raw.datasets[0].classes}")
print(f"Class to index mapping: {combined_dataset_raw.datasets[0].class_to_idx}")
print(f"Total samples for K-Fold: {len(combined_dataset_raw)}")
if test_dataset:
    print(f"Test samples: {len(test_dataset)}")




# --- 4. Load DINOv2 Model (Pre-trained Backbone) ---
try:
    dino_model = timm.create_model('vit_base_patch16_224', pretrained=True)
    
    class DinoFeatureExtractor(nn.Module):
        def __init__(self, dino):
            super().__init__()
            self.dino = dino
        def forward(self, x):
            return self.dino.forward_features(x)[:, 0]

    pre_trained_dino_model = DinoFeatureExtractor(dino_model).to(device)
    pre_trained_dino_model.eval()
    for param in pre_trained_dino_model.parameters():
        param.requires_grad = False
    print("Pre-trained DINO model loaded and frozen for linear probing.")

except ImportError:
    print("timm library not found. Please install it using: pip install timm")
    raise
except Exception as e:
    raise ImportError(f"ERROR loading DINOv2 model: {e}. Check internet connection or timm installation.")

# --- 5. Linear Classifier Setup ---
class ClassifierWithDropout(nn.Module):
    def __init__(self, input_dim, num_classes):
        super().__init__()
        hidden_dim = 256
        self.fc = nn.Sequential(
            nn.Dropout(p=0.55),
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(p=0.55),
            nn.Linear(hidden_dim, num_classes)
        )
    def forward(self, x):
        return self.fc(x)



# --- 6. Training Loop (Stratified K-Fold Cross-Validation) ---
kf = StratifiedKFold(n_splits=NUM_FOLDS, shuffle=True, random_state=42)
print(f"\n--- Starting {NUM_FOLDS}-Fold Stratified Cross-Validation Training ---")

# Store the path to the overall best model across all folds
best_overall_val_loss = float('inf')
best_overall_classifier_path = os.path.join(classifier_save_dir, 'best_overall_classifier_weights.pth')


for fold, (train_indices, val_indices) in enumerate(kf.split(np.zeros(len(combined_dataset_raw)), all_targets)):
    print(f"\n--- Starting Fold {fold+1}/{NUM_FOLDS} ---")

    train_subset = DatasetWithTransform(combined_dataset_raw, train_indices, transform=train_transform)
    val_subset = DatasetWithTransform(combined_dataset_raw, val_indices, transform=val_transform)
    
    train_targets_fold = [all_targets[i] for i in train_indices]
    class_counts = Counter(train_targets_fold)
    class_weights = torch.tensor([1.0 / class_counts[i] for i in range(num_classes)], dtype=torch.float32)
    class_weights = class_weights.to(device)
    print(f"  Fold {fold+1} Train class counts: {class_counts}")
    print(f"  Fold {fold+1} Train class weights: {class_weights}")
    
    train_loader = DataLoader(train_subset, batch_size=BATCH_SIZE, shuffle=True, num_workers=NUM_WORKERS)
    val_loader = DataLoader(val_subset, batch_size=BATCH_SIZE, shuffle=False, num_workers=NUM_WORKERS)

    linear_classifier = ClassifierWithDropout(dino_backbone_dim, num_classes).to(device)
    criterion_cls = nn.CrossEntropyLoss(weight=class_weights)
    optimizer_cls = optim.Adam(linear_classifier.parameters(), lr=0.0002, weight_decay=5e-3)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer_cls, mode='min', factor=0.2, patience=5
    )

    fold_train_losses, fold_val_losses = [], []
    fold_train_accuracies, fold_val_accuracies = [], []
    best_val_loss = float('inf')
    best_val_accuracy = 0.0
    epochs_no_improve = 0
    
    best_classifier_path = os.path.join(classifier_save_dir, f'best_linear_classifier_fold_{fold+1}.pth')
    
    for epoch in range(EPOCHS):
        linear_classifier.train()
        total_loss, correct, total = 0, 0, 0
        
        for images, labels in tqdm(train_loader, desc=f"[Fold {fold+1}, Epoch {epoch+1}] Training"):
            images, labels = images.to(device), labels.to(device)
            optimizer_cls.zero_grad()
            with torch.no_grad():
                features = pre_trained_dino_model(images)
            outputs = linear_classifier(features)
            loss = criterion_cls(outputs, labels)
            loss.backward()
            optimizer_cls.step()
            total_loss += loss.item() * images.size(0)
            correct += (outputs.argmax(1) == labels).sum().item()
            total += labels.size(0)

        train_acc = correct / total
        train_loss = total_loss / total
        
        linear_classifier.eval()
        val_loss, val_correct, val_total = 0, 0, 0
        val_preds = []
        val_true = []
        with torch.no_grad():
            for images, labels in tqdm(val_loader, desc=f"[Fold {fold+1}, Epoch {epoch+1}] Validation"):
                images, labels = images.to(device), labels.to(device)
                features = pre_trained_dino_model(images)
                outputs = linear_classifier(features)
                val_loss += criterion_cls(outputs, labels).item() * images.size(0)
                predicted = outputs.argmax(1)
                val_correct += (predicted == labels).sum().item()
                val_total += labels.size(0)
                val_preds.extend(predicted.cpu().numpy())
                val_true.extend(labels.cpu().numpy())

        val_acc = val_correct / val_total
        val_loss /= val_total
        
        fold_train_losses.append(train_loss)
        fold_val_losses.append(val_loss)
        fold_train_accuracies.append(train_acc)
        fold_val_accuracies.append(val_acc)
        
        print(f"[Fold {fold+1}, Epoch {epoch+1}] Train Loss: {train_loss:.4f}, Acc: {train_acc:.4f} | Val Loss: {val_loss:.4f}, Acc: {val_acc:.4f}")
        
        scheduler.step(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_val_accuracy = val_acc
            torch.save(linear_classifier.state_dict(), best_classifier_path)
            print(f"--> New best model for Fold {fold+1} saved (Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f})\n")
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            print(f"No improvement in validation loss for Fold {fold+1}. Patience counter: {epochs_no_improve}/{PATIENCE}")
            if epochs_no_improve >= PATIENCE:
                print(f"Early stopping triggered for Fold {fold+1}.")
                break

    all_fold_best_acc.append(best_val_accuracy)
    all_fold_best_loss.append(best_val_loss)
    plot_fold_train_losses.append(fold_train_losses)
    plot_fold_val_losses.append(fold_val_losses)
    plot_fold_train_accuracies.append(fold_train_accuracies)
    plot_fold_val_accuracies.append(fold_val_accuracies)
    
    linear_classifier.load_state_dict(torch.load(best_classifier_path))
    linear_classifier.eval()
    with torch.no_grad():
        val_preds_best_fold = []
        val_true_best_fold = []
        for images, labels in val_loader:
            images, labels = images.to(device), labels.to(device)
            features = pre_trained_dino_model(images)
            outputs = linear_classifier(features)
            predicted = outputs.argmax(1)
            val_preds_best_fold.extend(predicted.cpu().numpy())
            val_true_best_fold.extend(labels.cpu().numpy())
    
    fold_val_precision.append(precision_score(val_true_best_fold, val_preds_best_fold, average='weighted', zero_division=0))
    fold_val_recall.append(recall_score(val_true_best_fold, val_preds_best_fold, average='weighted', zero_division=0))
    fold_val_f1.append(f1_score(val_true_best_fold, val_preds_best_fold, average='weighted', zero_division=0))
    
print("\n--- K-Fold Training Complete ---")
print(f"Best Validation Accuracies per fold: {all_fold_best_acc}")
print(f"Average Best Validation Accuracy: {np.mean(all_fold_best_acc):.4f}")
print(f"Average Best Validation Loss: {np.mean(all_fold_best_loss):.4f}")
print(f"Average Validation Precision: {np.mean(fold_val_precision):.4f}")
print(f"Average Validation Recall: {np.mean(fold_val_recall):.4f}")
print(f"Average Validation F1-Score: {np.mean(fold_val_f1):.4f}")


# --- 7. Load Best Model (from the fold with the lowest validation loss) and Evaluate on Test Set ---
best_overall_classifier = ClassifierWithDropout(dino_backbone_dim, num_classes).to(device)
best_overall_val_loss_index = np.argmin(all_fold_best_loss)
final_model_path = os.path.join(classifier_save_dir, f'best_linear_classifier_fold_{best_overall_val_loss_index + 1}.pth')

if os.path.exists(final_model_path):
    print(f"\nLoading best overall model for final test evaluation: {final_model_path}")
    best_overall_classifier.load_state_dict(torch.load(final_model_path))
    best_overall_classifier.eval()
else:
    print(f"Warning: Best overall model not found at {final_model_path}. Skipping final evaluation.")
    best_overall_classifier = None

if test_loader and best_overall_classifier:
    test_loss, test_correct, test_total = 0, 0, 0
    all_preds = []
    all_labels = []
    
    criterion_cls = nn.CrossEntropyLoss()

    with torch.no_grad():
        for images, labels in tqdm(test_loader, desc="Testing"):
            images, labels = images.to(device), labels.to(device)
            features = pre_trained_dino_model(images)
            outputs = best_overall_classifier(features)
            test_loss += criterion_cls(outputs, labels).item() * images.size(0)
            predicted = outputs.argmax(1)
            test_correct += (predicted == labels).sum().item()
            test_total += labels.size(0)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    test_acc = test_correct / test_total
    test_loss /= test_total
    print(f"\nFinal Test Loss: {test_loss:.4f}, Final Test Accuracy: {test_acc:.4f}")
    
    print("\n--- Test Set Classification Report ---")
    print(classification_report(all_labels, all_preds, target_names=target_class_names, zero_division=0))
    
    print("\n--- Test Set Confusion Matrix ---")
    cm = confusion_matrix(all_labels, all_preds)
    print(cm)
else:
    print("Skipping test set evaluation as no test directory or final model was found.")

# --- 8. Plotting Loss and Accuracy Curves (Per-Fold) ---
def exponential_moving_average(data, span=5):
    if not data:
        return []
    smoothed_data = [data[0]]
    for i in range(1, len(data)):
        smoothed_data.append((data[i] * (2 / (span + 1))) + (smoothed_data[-1] * (1 - (2 / (span + 1)))))
    return smoothed_data

plt.figure(figsize=(16, 8))
plt.subplot(2, 2, 1)
for i, losses in enumerate(plot_fold_train_losses):
    smoothed_losses = exponential_moving_average(losses, span=5)
    plt.plot(smoothed_losses, label=f'Fold {i+1} Train Loss', alpha=0.7)
plt.title('Train Loss per Fold (Smoothed)')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend(loc='upper right', fontsize='small')
plt.grid(True, linestyle='--', alpha=0.6)

plt.subplot(2, 2, 2)
for i, losses in enumerate(plot_fold_val_losses):
    smoothed_losses = exponential_moving_average(losses, span=5)
    plt.plot(smoothed_losses, label=f'Fold {i+1} Val Loss', alpha=0.7)
plt.title('Validation Loss per Fold (Smoothed)')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend(loc='upper right', fontsize='small')
plt.grid(True, linestyle='--', alpha=0.6)

plt.subplot(2, 2, 3)
for i, accs in enumerate(plot_fold_train_accuracies):
    smoothed_accs = exponential_moving_average(accs, span=5)
    plt.plot(smoothed_accs, label=f'Fold {i+1} Train Acc', alpha=0.7)
plt.title('Train Accuracy per Fold (Smoothed)')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend(loc='lower right', fontsize='small')
plt.grid(True, linestyle='--', alpha=0.6)

plt.subplot(2, 2, 4)
for i, accs in enumerate(plot_fold_val_accuracies):
    smoothed_accs = exponential_moving_average(accs, span=5)
    plt.plot(smoothed_accs, label=f'Fold {i+1} Val Acc', alpha=0.7)
plt.title('Validation Accuracy per Fold (Smoothed)')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend(loc='lower right', fontsize='small')
plt.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.show()


# --- 9. Grad-CAM Visualization with Optimized Implementation ---
print("\n--- Generating Grad-CAM Heatmaps for Test Samples ---")

if best_overall_classifier and test_loader:
    # A custom model class is needed to connect the backbone and classifier for Grad-CAM
    class FullModelForCAM(nn.Module):
        def __init__(self, backbone, classifier):
            super().__init__()
            self.backbone = backbone
            self.classifier = classifier
        
        def forward(self, x):
            # The backbone returns a tensor of all tokens, including the [CLS] token at index 0
            features = self.backbone.forward_features(x)
            
            # The classifier part only needs the CLS token (the first one)
            cls_token_features = features[:, 0]
            
            # The classifier then produces logits
            logits = self.classifier(cls_token_features)
            return logits

    # Create a new DINOv2 model instance for CAM to ensure gradients can be computed
    cam_dino_model = timm.create_model('vit_base_patch16_224', pretrained=True).to(device)
    cam_dino_model.eval()

    # Combine the backbone and the trained classifier
    full_model_for_cam = FullModelForCAM(cam_dino_model, best_overall_classifier).to(device)
    full_model_for_cam.eval()

    # This reshape transform is CRUCIAL for Vision Transformers.
    # It takes the output of the ViT (a sequence of tokens) and reshapes it into a 2D grid.
    def reshape_transform_vit(tensor, height=14, width=14):
        # We drop the first token (the CLS token) and reshape the rest
        result = tensor[:, 1:, :].reshape(tensor.size(0), height, width, tensor.size(2))
        
        # We then transpose the tensor to the required (B, C, H, W) format
        result = result.transpose(2, 3).transpose(1, 2)
        return result

    # The target layer for ViT is typically the last attention block
    target_layer = cam_dino_model.blocks[-1].attn
    
    # Initialize Grad-CAM with the full model and the correct reshape function
    cam = GradCAM(model=full_model_for_cam, target_layers=[target_layer], reshape_transform=reshape_transform_vit)
    
    num_samples_to_visualize = 5
    if test_dataset and len(test_dataset) > 0:
        sample_indices = np.random.choice(len(test_dataset), min(num_samples_to_visualize, len(test_dataset)), replace=False)
    else:
        sample_indices = np.array([])
    
    if len(sample_indices) > 0:
        plt.figure(figsize=(20, 5 * len(sample_indices)))
        
        for i, idx in enumerate(sample_indices):
            img_tensor, true_label = test_dataset[idx]
            img_tensor_for_cam = img_tensor.unsqueeze(0).to(device)
            original_img_np = denormalize_image(img_tensor).permute(1, 2, 0).cpu().numpy()
            
            # Get the predictions from the full model
            with torch.no_grad():
                outputs = full_model_for_cam(img_tensor_for_cam)
            
            predicted_label_idx = outputs.argmax(1).item()
            predicted_class = target_class_names[predicted_label_idx]
            true_class = target_class_names[true_label]
            probabilities = torch.softmax(outputs, dim=1)
            
            # --- Visualization ---
            plt.subplot(len(sample_indices), 3, i * 3 + 1)
            plt.imshow(original_img_np)
            plt.title(f"Original\nTrue: {true_class}, Pred: {predicted_class} ({probabilities[0, predicted_label_idx].item():.2f})")
            plt.axis('off')
            
            # Generate the Grad-CAM heatmap for the predicted class
            grayscale_cam_pred = cam(input_tensor=img_tensor_for_cam, targets=[ClassifierOutputTarget(predicted_label_idx)])[0, :]
            visualization_overlay_pred = show_cam_on_image(original_img_np, grayscale_cam_pred, use_rgb=True, image_weight=0.5)
            
            plt.subplot(len(sample_indices), 3, i * 3 + 2)
            plt.imshow(visualization_overlay_pred)
            plt.title(f"CAM for Predicted '{predicted_class}'")
            plt.axis('off')
            
            # Generate the Grad-CAM heatmap for the true class
            grayscale_cam_true = cam(input_tensor=img_tensor_for_cam, targets=[ClassifierOutputTarget(true_label)])[0, :]
            visualization_overlay_true = show_cam_on_image(original_img_np, grayscale_cam_true, use_rgb=True, image_weight=0.5)
            
            plt.subplot(len(sample_indices), 3, i * 3 + 3)
            plt.imshow(visualization_overlay_true)
            plt.title(f"CAM for True '{true_class}'")
            plt.axis('off')
        
        plt.tight_layout()
        plt.show()
    else:
        print("No test samples available for Grad-CAM visualization.")
else:
    print("Skipping Grad-CAM visualization as no test directory or final model was found.")



