from PIL import Image, ImageDraw, ImageEnhance
from skimage import measure
import numpy as np
import cv2

imagem = Image.open('mama.jpg')

imagem_cinza = imagem.convert('L')

matriz_imagem = np.array(imagem_cinza)

contornos = measure.find_contours(matriz_imagem, 0.8)

desenhar = ImageDraw.Draw(imagem)
for contorno in contornos:
    for i in range(len(contorno) - 1):
        desenhar.line((contorno[i][1], contorno[i][0], contorno[i+1][1], contorno[i+1][0]), fill='red', width=2)

realcar = ImageEnhance.Contrast(imagem)
imagem = realcar.enhance(15.5)

imagem.save('mama_contornos.jpg')