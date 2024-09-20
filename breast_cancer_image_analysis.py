import cv2
import numpy as np
img = cv2.imread("mama_contornos.jpg")

numero_pixels_branco = np.sum(img == 255)
numero_pixels_preto = np.sum(img == 0)
print('Número de pixels brancos:', numero_pixels_branco)
print('Número de pixels pretos:', numero_pixels_preto)

percentual_pixels_brancos = numero_pixels_branco / (numero_pixels_branco + numero_pixels_preto) * 100
print('Percentual de pixels brancos:', percentual_pixels_brancos)

if percentual_pixels_brancos >= 30:
    print('Imagem com câncer')
else:
    print('Imagem sem câncer')
