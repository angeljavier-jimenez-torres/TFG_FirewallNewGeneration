# Detección de Ataques de Denegación de Servicio (DoS) con Random Forest

Este proyecto tiene como objetivo desarrollar y evaluar un modelo de aprendizaje automático basado en Random Forest para la detección de ataques de denegación de servicio (DoS). 

## Descripción del Proyecto

Los ataques de denegación de servicio (DoS) son un tipo de ataque cibernético en el que el atacante intenta hacer que un recurso de la red sea inaccesible para sus usuarios legítimos. Este proyecto utiliza técnicas de aprendizaje automático para identificar tales ataques y mitigar sus efectos.

El modelo Random Forest es elegido por su robustez y capacidad para manejar grandes conjuntos de datos con múltiples características, proporcionando una alta precisión en la clasificación de tráfico de red como legítimo o malicioso.

## Contenido del Repositorio

- `DataSet_CIC-DDoS2019/`: Contiene los conjuntos de datos utilizados para entrenar y probar el modelo, en formato zip. Asi como los ficheros y el conjunto de datos unido preprocesados
- `notebooks/`: Jupyter notebooks con el análisis exploratorio de datos (EDA), preprocesamiento y entrenamiento del modelo. También se encuentran la selección de características y el modelo en formato CSV.
Puedes instalar las dependencias necesarias usando pip:
    ```bash
    pip install -r requirements.txt
    ```

- `docker/`: Incluye tanto el backend como el frontend de la aplicación, para ejecutarlo, se debe escribir el siguiente comando:

    ```bash
    docker-compose up --build
    ```


