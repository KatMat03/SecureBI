import pandas as pd
import streamlit as st

# --- KONFIGURACJA STRONY ---
st.set_page_config(
    page_title="BI Security PoC",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- NAGŁÓWEK ---
st.title("System BI - Analiza Bezpieczeństwa Dashboardów")
st.caption(
    "Przedmiot: Bezpieczeństwo Hurtowni Danych | Kategoria: Cyberataki,"
    " wykrywanie zagrożeń i reagowanie na incydenty"
)
st.markdown("---")


# --- WARSTWA DANYCH I CACHE ---
@st.cache_data(ttl=60, show_spinner="Ładowanie danych...")
def nacztytaj_dane() -> pd.DataFrame:
  """Wczytuje dane z pliku Excela z ograniczeniem czasu życia pamięci podręcznej (TTL = 60s)."""
  return pd.read_excel("dane_firmowe.xlsx")


try:
  df = nacztytaj_dane()
except FileNotFoundError:
  st.error(
      "Błąd: Nie odnaleziono pliku 'dane_firmowe.xlsx' w katalogu roboczym."
  )
  st.stop()

# --- AUTORYZACJA I PANEL RBAC ---
st.sidebar.header("Kontrola Dostępu (RBAC)")
rola = st.sidebar.selectbox(
    "Rola użytkownika:",
    ["Zwykły Pracownik (User)", "Administrator (Admin)"],
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Parametry sesji:**")
st.sidebar.text("• Dostęp anonimowy: Zablokowany")
st.sidebar.text("• Pamięć podręczna (TTL): 60 s")
st.sidebar.text("• Model autoryzacji: RBAC")

# --- WIDOK ZAGREGOWANY (BEZPIECZNY) ---
st.subheader("Wskaźniki Biznesowe: Wynagrodzenia w Działach")
st.caption(
    "Widok zagregowany – dostępny dla wszystkich ról zgodnie z zasadą"
    " najmniejszych uprawnień."
)

srednie_pensje = df.groupby("Dzial")["Pensja"].mean().reset_index()
srednie_pensje.columns = ["Dział", "Średnie Wynagrodzenie"]

col_chart, col_table = st.columns([2, 1])
with col_chart:
  st.bar_chart(srednie_pensje.set_index("Dział"))
with col_table:
  st.dataframe(srednie_pensje, hide_index=True, use_container_width=True)

# --- MODUŁ EKSPORTU I KONTROLI WYCIEKU DANYCH ---
st.markdown("---")
st.subheader("Moduł Eksportu Danych")

if rola == "Administrator (Admin)":
  st.info(
      "Zalogowano jako Administrator. Dostęp do pełnej bazy danych przyznany."
  )
  st.dataframe(df, use_container_width=True)

  csv_full = df.to_csv(index=False).encode("utf-8")
  st.download_button(
      label="Pobierz pełny raport CSV (Surowe dane)",
      data=csv_full,
      file_name="raport_poufny_full.csv",
      mime="text/csv",
  )

else:
  st.warning(
      "Brak uprawnień do pobierania surowych rekordu bazy (PESEL, zarobki"
      " indywidualne)."
  )
  st.write("Dostępna jest wyłącznie możliwość pobrania zestawienia zagregowanego:")

  csv_safe = srednie_pensje.to_csv(index=False).encode("utf-8")
  st.download_button(
      label="Pobierz zagregowany raport CSV",
      data=csv_safe,
      file_name="raport_bezpieczny_agregat.csv",
      mime="text/csv",
  )