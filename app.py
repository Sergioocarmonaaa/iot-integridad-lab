# app.py
import os
import time
import io
import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple, Optional, List

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# Reproducibilidad
np.random.seed(7)

# Page config
st.set_page_config(page_title="Mini-Lab IoT: Integridad & Capas", layout="wide")

# Header
st.title("Mini-Lab IoT — Integridad (HMAC) & Capas")
st.markdown(
    """
Mini-laboratorio para experimentar con integridad de datos (SHA-256 vs HMAC-SHA256)
y comprender trade-offs de protocolos IoT (ancho de banda, latencia y consumo).
"""
)

# Utilities: hashing
def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hmac_sha256(key: bytes, s: str) -> str:
    return hmac.new(key, s.encode("utf-8"), hashlib.sha256).hexdigest()

# SECRET: obtiene de Streamlit secrets si está definido; si no, usa os.urandom (no exponer)
SECRET_BYTES = None
try:
    # st.secrets stored as HMAC_SECRET string
    sec = st.secrets.get("HMAC_SECRET", None)
    if sec is not None:
        SECRET_BYTES = sec.encode("utf-8")
    else:
        SECRET_BYTES = os.urandom(16)
except Exception:
    SECRET_BYTES = os.urandom(16)

# Data classes
@dataclass
class Canal:
    loss_prob: float  # 0..1
    latency_ms_min: int
    latency_ms_max: int
    tamper_bias: float  # degrees added when tampering
    tamper_prob: float  # probability that packet is tampered

    def transmit(self, value: float, tampering_on: bool) -> Tuple[Optional[float], dict]:
        """
        Simula la transmisión de un único paquete.
        Devuelve (received_value_or_None_if_lost, metadata)
        """
        meta = {"lost": False, "latency_ms": 0, "tampered": False}
        # Loss
        if np.random.rand() < self.loss_prob:
            meta["lost"] = True
            return None, meta

        # Latency
        meta["latency_ms"] = int(np.random.uniform(self.latency_ms_min, self.latency_ms_max))

        rx = float(value)

        # Tampering
        if tampering_on and np.random.rand() < self.tamper_prob:
            rx += self.tamper_bias
            meta["tampered"] = True

        return rx, meta

# --- Layout: tabs ---
tabs = st.tabs(["Sesión 1 — Integridad (HMAC)", "Sesión 2 — Capas IoT", "Caso & Entregables"])

# ---------------------------
# SESIÓN 1 — Integridad (HMAC)
# ---------------------------
with tabs[0]:
    st.header("Sesión 1 — Integridad de datos (SHA-256 vs HMAC-SHA256)")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Controles de la simulación")
        duration_s = st.slider("Duración de la simulación (segundos)", min_value=5, max_value=60, value=20, step=1)
        loss_prob = st.slider("Probabilidad de pérdida por paquete (0–0.30)", min_value=0.0, max_value=0.30, value=0.05, step=0.01)
        tampering_on = st.checkbox("Tampering (ON/OFF)", value=True)
        verification_mode = st.selectbox("Verificación de integridad", options=["None", "SHA", "HMAC"], index=2)
        add_export = st.checkbox("Habilitar botón Exportar CSV (muestras recibidas)", value=True)

        # Optional: tamper_bias selector (extensión compacta)
        tamper_bias = st.slider("tamper_bias (°C) — desviación si se manipula", min_value=5.0, max_value=20.0, value=10.0, step=1.0)

        # Canal: latency range simple didáctico
        latency_min = st.number_input("Latencia mínima (ms)", value=50, step=10)
        latency_max = st.number_input("Latencia máxima (ms)", value=200, step=10)

        # Canal tamper probability
        tamper_prob = st.slider("Probabilidad de manipulación por paquete", min_value=0.0, max_value=1.0, value=0.25, step=0.05)

        run_sim = st.button("Ejecutar simulación")

    with col2:
        st.subheader("Clave HMAC (fuente)")
        st.markdown(
            """
        La clave HMAC se lee desde **Streamlit Secrets** (nombre `HMAC_SECRET`) si está definida.
        Si no existe, se usa una clave aleatoria temporal (no guardada).
        **En producción la clave debe estar en secrets**, no en el código.
        """
        )
        # Show whether secret exists (but do not print the value in production; show masked)
        try:
            if st.secrets.get("HMAC_SECRET", None):
                st.success("HMAC_SECRET encontrado en Streamlit Secrets (se usa clave fija).")
            else:
                st.info("No hay HMAC_SECRET en Secrets → se usa clave aleatoria temporal.")
        except Exception:
            st.info("No hay HMAC_SECRET en Secrets → se usa clave aleatoria temporal.")

    # Simulation area
    placeholder_plot = st.empty()
    placeholder_metrics = st.empty()

    # Storage for samples (to allow export)
    samples: List[dict] = []

    if run_sim:
        # Prepare channel
        canal = Canal(loss_prob=float(loss_prob),
                      latency_ms_min=int(latency_min),
                      latency_ms_max=int(latency_max),
                      tamper_bias=float(tamper_bias),
                      tamper_prob=float(tamper_prob))

        st.info("Iniciando simulación... (la UI se actualizará en tiempo real).")
        # Sensor model: base temp with noise and small drift
        base_temp = 60.0  # °C (e.g., caldera)
        drift_per_sample = 0.005  # small upward drift
        sample_interval = 0.25  # s
        n_samples = int(duration_s / sample_interval)

        times = []
        temps_sent = []
        temps_rx = []
        verification_fail_idxs = []
        tampered_flags = []
        lost_count = 0
        verification_fails = 0

        # Reset random seed for reproducible runs in the UI run
        np.random.seed(7)

        t0 = 0.0
        current_temp = base_temp + np.random.normal(0, 0.2)
        for i in range(n_samples):
            # simulate sensor reading
            noise = np.random.normal(0, 0.15)
            current_temp = current_temp + drift_per_sample + noise
            payload = f"{current_temp:.4f}"

            # Sender computes integrity tag depending on chosen verification used on receiver:
            # - If we want to show the weakness of SHA, assume attacker can recompute SHA if tampering.
            # - Attacker cannot compute HMAC without key.
            # The sender always computes both (as if device would attach both); emulate that the receiver uses one method.
            sha_tag = sha256_str(payload)
            hmac_tag = hmac_sha256(SECRET_BYTES, payload)

            # Send through channel; channel may tamper the payload
            rx_value, meta = canal.transmit(current_temp, tampering_on)

            if meta["lost"] or rx_value is None:
                # lost sample
                lost_count += 1
                # still store a log entry
                samples.append({
                    "time": t0,
                    "sent_temp": current_temp,
                    "received_temp": None,
                    "lost": True,
                    "tampered": False,
                    "verification_mode": verification_mode,
                    "verification_ok": None
                })
                # update plot every iteration for responsiveness
                times.append(t0)
                temps_sent.append(current_temp)
                temps_rx.append(np.nan)
                tampered_flags.append(False)
                t0 += sample_interval
                # update plot/metrics
                # draw
                fig, ax = plt.subplots(figsize=(9, 3))
                ax.plot(times, temps_sent, label="Temp. sensor (sent)", linewidth=1)
                ax.plot(times, temps_rx, label="Temp. recibida", linewidth=1)
                ax.set_xlabel("t (s)")
                ax.set_ylabel("Temperatura (°C)")
                ax.legend(loc="upper left")
                ax.set_title("Streaming (paquetes perdidos omitidos en rx)")
                placeholder_plot.pyplot(fig)
                placeholder_metrics.markdown(f"Samples: {i+1}  |  Perdidos: {lost_count}")
                time.sleep(0.01)
                continue

            # If tampered, attacker may recompute SHA but not HMAC.
            tampered = meta["tampered"]
            received_payload = f"{rx_value:.4f}"

            # Simulate tag attached by sender; if attacker tampers and verification is SHA,
            # attacker can also recompute SHA tag and replace it -> SHA will not detect.
            # If verification is HMAC and attacker tampers, they cannot recompute HMAC (no key), so verification fails.
            # Emulate receiver verifying based on verification_mode.
            verification_ok = True
            if verification_mode == "None":
                verification_ok = None  # no verification applied
            elif verification_mode == "SHA":
                # If tampered, attacker recomputes SHA -> verification passes (so SHA cannot detect)
                # If not tampered, verification passes if payload unchanged
                expected = sha256_str(received_payload)
                # Emulate attacker recomputing expected if tampered (so passes)
                verification_ok = (expected == sha_tag) or tampered
                # Note: in this simplified sim we treat tampered as attacker recomputing tag -> pass
            elif verification_mode == "HMAC":
                # If tampered and attacker can't compute HMAC, verification fails.
                expected = hmac_sha256(SECRET_BYTES, received_payload)
                # If not tampered, expected == sender hmac_tag
                if tampered:
                    # attacker cannot recompute HMAC -> mismatch
                    verification_ok = False
                else:
                    verification_ok = (expected == hmac_tag)

            # Bookkeeping
            samples.append({
                "time": t0,
                "sent_temp": current_temp,
                "received_temp": rx_value,
                "lost": False,
                "tampered": tampered,
                "verification_mode": verification_mode,
                "verification_ok": verification_ok
            })
            times.append(t0)
            temps_sent.append(current_temp)
            temps_rx.append(rx_value)
            tampered_flags.append(tampered)
            if verification_ok is False:
                verification_fails += 1
                verification_fail_idxs.append(len(times) - 1)

            # Plot update (matplotlib)
            fig, ax = plt.subplots(figsize=(9, 3))
            ax.plot(times, temps_sent, label="Temp. sensor (sent)", linewidth=1)
            ax.plot(times, temps_rx, label="Temp. recibida", linewidth=1)
            # mark tampered points with orange x
            tampered_x = [times[idx] for idx,flag in enumerate(tampered_flags) if flag]
            tampered_y = [temps_rx[idx] if not np.isnan(temps_rx[idx]) else np.nan for idx,flag in enumerate(tampered_flags) if flag]
            if tampered_x:
                ax.scatter(tampered_x, tampered_y, marker="x", s=40, label="Tampered (detected by inspection)", zorder=5)

            # mark verification failures as red dots
            if verification_fail_idxs:
                vx = [times[idx] for idx in verification_fail_idxs]
                vy = [temps_rx[idx] for idx in verification_fail_idxs]
                ax.scatter(vx, vy, color="red", s=30, label="Fallo integridad (verificación)", zorder=6)

            ax.set_xlabel("t (s)")
            ax.set_ylabel("Temperatura (°C)")
            ax.legend(loc="upper left")
            ax.set_title("Streaming de lecturas (actualiza en tiempo real)")
            placeholder_plot.pyplot(fig)

            # Metrics summary
            summary_md = f"""
            **Muestras enviadas:** {i+1}  
            **Perdidas (packet loss):** {lost_count}  
            **Tampering (on):** {tampering_on}  (prob. por paquete: {tamper_prob:.2f}, bias: {tamper_bias}°C)  
            **Verificación:** {verification_mode}  
            **Fallos detección integridad:** {verification_fails}
            """
            placeholder_metrics.markdown(summary_md)

            # sleep to simulate streaming (non-blocking-ish)
            time.sleep(sample_interval)
            t0 += sample_interval

        # End simulation: final summary and export
        st.success("Simulación completada.")
        df = pd.DataFrame(samples)
        st.markdown("### Resumen final")
        st.write(df.describe(include="all"))

        # Export CSV button (optional)
        if add_export:
            csv = df.to_csv(index=False)
            st.download_button("Exportar CSV de muestras", data=csv, file_name="muestras_sesion1.csv", mime="text/csv")

        # Observaciones pedagógicas
        st.markdown("### Qué observar")
        st.markdown(
            """
- **SHA-256 (hash simple)**: si un atacante puede manipular el paquete *y* recomputar el hash (porque no requiere clave), el receptor no podrá distinguir la manipulación. En nuestra simulación hemos modelado ese comportamiento: cuando **Tampering = ON** y la verificación es **SHA**, el atacante **puede** recomputar el hash y la verificación no detecta la alteración.
- **HMAC-SHA256**: requiere una clave secreta (HMAC_SECRET). Si el atacante no tiene la clave, no puede recomputar la etiqueta HMAC tras manipular la lectura; por tanto, la verificación HMAC detectará la manipulación (aparecen puntos rojos).
- **Conclusión**: HMAC añade autenticación de origen e integridad con una clave secreta; un hash simple sólo provee integridad condicional si la etiqueta es inmutable o firmada por un tercero de confianza.
            """
        )

# ---------------------------
# SESIÓN 2 — Capas IoT
# ---------------------------
with tabs[1]:
    st.header("Sesión 2 — Capas IoT: protocolo, #sensores, BW, latencia y consumo")
    st.markdown("Selecciona parámetros y observa el cálculo didáctico de ancho de banda, latencia y score heurístico.")

    protocols = {
        "WiFi": {"bw_kbps": 10000, "latency_ms": 20, "consumption_mA": 200},
        "LoRaWAN": {"bw_kbps": 50, "latency_ms": 1000, "consumption_mA": 30},
        "Zigbee": {"bw_kbps": 250, "latency_ms": 50, "consumption_mA": 50},
        "NB-IoT": {"bw_kbps": 200, "latency_ms": 200, "consumption_mA": 100}
    }

    colp1, colp2 = st.columns(2)
    with colp1:
        proto = st.selectbox("Protocolo de red", options=list(protocols.keys()), index=1)
        n_sensors = st.slider("Número de sensores", min_value=1, max_value=20, value=5, step=1)
        alerts_on = st.checkbox("Alertas activas (cada sensor envia alertas frecuentes)", value=True)

    with colp2:
        st.markdown("Parámetros didácticos del enlace")
        proto_info = protocols[proto]
        st.write(proto_info)

    # Didactic calculation
    bw_available = protocols[proto]["bw_kbps"]  # in kbps
    latency = protocols[proto]["latency_ms"]
    consumption = protocols[proto]["consumption_mA"]

    bytes_per_sec_per_sensor = (2 * 1000) / 8.0  # 2 kbps per sensor -> it's already kbps; convert? keep as kbps (2 kbps)
    # As requested: BW requerido = 2 kbps por sensor
    bw_required = n_sensors * 2.0  # in kbps

    ok_bw = bw_required <= bw_available

    # Score heurístico (0..100)
    # Combine normalized components: bw_ratio (capped at 1), latency (inverse), consumption (inverse)
    bw_score = min(bw_available / max(bw_required, 0.0001), 2.0) / 2.0  # 0..1 (>=1 -> 1)
    latency_score = max(0.0, 1.0 - (latency / 2000.0))  # assume 2000ms worst limit
    consumption_score = max(0.0, 1.0 - (consumption / 500.0))  # assume 500mA worst

    # If alerts_on, penalize consumption and latency importance
    weight_bw = 0.5
    weight_latency = 0.3
    weight_consumption = 0.2
    if alerts_on:
        weight_latency += 0.05
        weight_consumption -= 0.05

    score = (bw_score * weight_bw + latency_score * weight_latency + consumption_score * weight_consumption) * 100
    score = float(np.clip(score, 0, 100))

    st.markdown("### Resultados calculados")
    st.metric("BW disponible (kbps)", f"{bw_available:.1f}")
    st.metric("BW requerido (kbps)", f"{bw_required:.1f}", delta=None)
    st.metric("Latencia típica (ms)", f"{latency}")
    st.metric("Consumo por nodo (mA)", f"{consumption}")
    st.metric("Score heurístico", f"{score:.1f} / 100")

    # Bar chart: BW requerido vs disponible (matplotlib)
    fig2, ax2 = plt.subplots(figsize=(6, 3))
    labels = ["Requerido (kbps)", "Disponible (kbps)"]
    values = [bw_required, bw_available]
    ax2.bar(labels, values)
    ax2.set_title(f"BW requerido vs disponible — {proto} — sensores: {n_sensors}")
    ax2.set_ylim(0, max(bw_available, bw_required) * 1.2)
    ax2.set_ylabel("kbps")
    st.pyplot(fig2)

    st.markdown("### Interpretación rápida")
    st.markdown(
        f"""
- Con **{n_sensors}** sensores y un requerimiento simple de **2 kbps** por sensor, el BW requerido es **{bw_required:.1f} kbps**.
- Protocolos como **{proto}** ofrecen **{bw_available:.1f} kbps**. ¿Suficiente? → **{ok_bw}**.
- El *score* heurístico combina disponibilidad de BW, latencia y consumo en un único valor (0..100) para comparar rápidamente alternativas.
        """
    )

# ---------------------------
# TAB: Caso & Entregables
# ---------------------------
with tabs[2]:
    st.header("Caso & Entregables")
    st.markdown("Instrucciones para los alumnos sobre qué entregar tras realizar las dos sesiones.")

    # Try to link to docs/caso.pdf if exists in repo (when deployed it will be in the app folder).
    try:
        if os.path.exists("docs/caso.pdf"):
            st.markdown("[Descargar caso (docs/caso.pdf)](docs/caso.pdf)")
        else:
            st.info("No se encontró docs/caso.pdf — se muestra un placeholder con el caso resumido abajo.")
    except Exception:
        st.info("No se encontró docs/caso.pdf — se muestra un placeholder con el caso resumido abajo.")

    st.subheader("Entregables (por sesión)")

    st.markdown(
        """
**Sesión 1 (Integridad)**  
- Ejecutar la simulación con **Tampering = ON** y **Verificación = HMAC**.  
- Captura de pantalla del gráfico con los puntos rojos (fallos de integridad) y el recuento de fallos.  
- Entregar 3 líneas de reflexión personal sobre por qué HMAC detecta manipulación y limitaciones del ejemplo.

**Sesión 2 (Capas IoT)**  
- Ejecutar con un protocolo elegido (WiFi/LoRaWAN/Zigbee/NB-IoT) y un nº de sensores.  
- Captura del bar chart (BW requerido vs disponible).  
- Entregar 3 líneas justificando el trade-off latencia/energía y por qué ese protocolo se ajusta (o no) al escenario.
        """
    )

    st.subheader("Checklist de verificación (docente)")
    st.markdown(
        """
- [ ] Sesión 1: Con **Tampering ON + HMAC** aparecen puntos rojos y aumenta el contador "Fallos detección integridad".  
- [ ] Sesión 2: El bar chart responde al #Sensores y al Protocolo y el **score** cambia con latencia/consumo.  
- [ ] Los alumnos suben capturas + 3 líneas para cada sesión.
        """
    )

    st.subheader("Nota docente breve")
    st.markdown(
        """
Este mini-lab es **didáctico** y muestra la diferencia entre un hash simple (SHA) y un MAC (HMAC).  
**No** replique la gestión de claves en producción tal y como se hace aquí; use almacenes de secretos seguros y llaves por dispositivo.  
Se puede ampliar el laboratorio integrando firma asimétrica, hardware TPM/SE, o trazabilidad con registros (ledger).
        """
    )
