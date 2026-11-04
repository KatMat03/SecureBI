"""
SecureBI - PoC: bezpieczeństwo narzędzi BI i dashboardów
Projekt: Bezpieczeństwo Hurtowni Danych
Zagrożenia: cache, eksport, współdzielenie raportów, brak szyfrowania (HTTPS)
Uruchomienie: streamlit run app.py
"""
import hashlib
import hmac
import secrets
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

PLIK = "dane_firmowe.xlsx"
MIN_GRUPA = 3          # minimalna liczebność grupy w agregatach (ochrona przed deanonimizacją)
LIMIT_BLEDOW = 3       # liczba błędnych logowań do blokady
CZAS_BLOKADY = 60      # sekundy

st.set_page_config(page_title="SecureBI", layout="wide")


# ======================================================================
# UŻYTKOWNICY (hasła przechowywane jako hash PBKDF2, nie jawnym tekstem)
# ======================================================================
def hash_pw(haslo: str) -> str:
    # DEMO: stała sól. W produkcji: osobna losowa sól dla każdego użytkownika.
    return hashlib.pbkdf2_hmac("sha256", haslo.encode(), b"demo-salt", 100_000).hex()


UZYTKOWNICY = {
    "admin": {"haslo": hash_pw("Admin123!"), "rola": "admin"},
    "kadry": {"haslo": hash_pw("Kadry123!"), "rola": "hr"},
    "jan": {"haslo": hash_pw("User123!"), "rola": "user"},
}


# ======================================================================
# WSPÓŁDZIELONY STAN SERWERA: log zdarzeń, blokady, linki
# ======================================================================
@st.cache_resource
def get_log() -> list:
    return []


@st.cache_resource
def get_blokady() -> dict:
    return {}


@st.cache_resource
def get_linki() -> dict:
    return {}


def log(uzytkownik: str, zdarzenie: str, szczegoly: str = "") -> None:
    get_log().append(
        {
            "czas": datetime.now().strftime("%H:%M:%S"),
            "uzytkownik": uzytkownik,
            "zdarzenie": zdarzenie,
            "szczegoly": szczegoly,
        }
    )


# ======================================================================
# DANE I MASKOWANIE
# ======================================================================
@st.cache_data(ttl=60, show_spinner="Ładowanie danych...")
def wczytaj() -> pd.DataFrame:
    df = pd.read_excel(PLIK, dtype={"PESEL": str})
    df["PESEL"] = df["PESEL"].astype(str).str.zfill(11)
    return df


def maskuj_pesel(p: str) -> str:
    return "*" * 7 + p[-4:]


def agregat(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby("Dzial", as_index=False).agg(
        Liczba=("ID", "count"), Srednia_pensja=("Pensja", "mean")
    )
    g = g[g["Liczba"] >= MIN_GRUPA].copy()
    g["Srednia_pensja"] = g["Srednia_pensja"].round(2)
    return g


def widok_dla_roli(df: pd.DataFrame, rola: str) -> pd.DataFrame:
    """Jedno miejsce, w którym decydujemy, co kto widzi (zasada najmniejszych uprawnień)."""
    if rola == "admin":
        return df
    if rola == "hr":
        d = df.copy()
        d["PESEL"] = d["PESEL"].map(maskuj_pesel)
        return d
    return agregat(df)


def bezpieczny_csv(df: pd.DataFrame) -> bytes:
    """Ochrona przed CSV/formula injection w Excelu (komórki zaczynające się od = + - @)."""
    d = df.copy()
    for kol in d.select_dtypes(include="object").columns:
        d[kol] = d[kol].map(
            lambda x: "'" + x if isinstance(x, str) and x[:1] in ("=", "+", "-", "@") else x
        )
    return d.to_csv(index=False).encode("utf-8-sig")


# ======================================================================
# LOGOWANIE + BLOKADA PO BŁĘDNYCH PRÓBACH (wykrywanie ataku brute-force)
# ======================================================================
def logowanie() -> None:
    st.sidebar.header("Logowanie")
    if "user" in st.session_state:
        u = st.session_state["user"]
        st.sidebar.success(f"Zalogowano: {u} ({UZYTKOWNICY[u]['rola']})")
        if st.sidebar.button("Wyloguj"):
            log(u, "WYLOGOWANIE")
            del st.session_state["user"]
            st.rerun()
        return

    with st.sidebar.form("login"):
        login = st.text_input("Login")
        haslo = st.text_input("Hasło", type="password")
        ok = st.form_submit_button("Zaloguj")
    st.sidebar.caption("Konta demo: admin / kadry / jan (hasła w instrukcji)")

    if not ok:
        return
    stan = get_blokady().setdefault(login, {"bledy": 0, "do": 0.0})
    if time.time() < stan["do"]:
        log(login, "BLOKADA", "próba logowania na zablokowane konto")
        st.sidebar.error("Konto czasowo zablokowane.")
        return
    u = UZYTKOWNICY.get(login)
    if u and hmac.compare_digest(u["haslo"], hash_pw(haslo)):
        stan["bledy"] = 0
        st.session_state["user"] = login
        log(login, "LOGOWANIE_OK")
        st.rerun()
    else:
        stan["bledy"] += 1
        log(login or "?", "LOGOWANIE_BLAD", f"błąd nr {stan['bledy']}")
        if stan["bledy"] >= LIMIT_BLEDOW:
            stan["do"] = time.time() + CZAS_BLOKADY
            stan["bledy"] = 0
            log(login or "?", "ALERT", "podejrzenie brute-force, konto zablokowane")
        st.sidebar.error("Błędny login lub hasło.")


# ======================================================================
# NAGŁÓWEK
# ======================================================================
st.title("SecureBI – bezpieczeństwo narzędzi BI i dashboardów")
st.caption(
    "Bezpieczeństwo Hurtowni Danych | Ryzyko ujawnienia informacji przez eksporty, "
    "cache, współdzielenie raportów i osadzone wizualizacje"
)

try:
    df = wczytaj()
except FileNotFoundError:
    st.error(f"Nie znaleziono pliku '{PLIK}' w katalogu z aplikacją.")
    st.stop()

logowanie()
user = st.session_state.get("user")
rola = UZYTKOWNICY[user]["rola"] if user else None

tab_dash, tab_cache, tab_eksport, tab_share, tab_https, tab_log = st.tabs(
    [
        "Dashboard",
        "1. Cache",
        "2. Eksport",
        "3. Udostępnianie",
        "4. HTTPS",
        "Logi i incydenty",
    ]
)

# ======================================================================
# DASHBOARD (wymaga logowania)
# ======================================================================
with tab_dash:
    if not user:
        st.warning("Zaloguj się, aby zobaczyć dashboard (dostęp anonimowy zablokowany).")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Liczba pracowników", len(df))
        c2.metric("Średnie wynagrodzenie", f"{df['Pensja'].mean():,.0f} zł")
        c3.metric("Liczba działów", df["Dzial"].nunique())

        ag = agregat(df)
        fig = px.bar(ag, x="Dzial", y="Srednia_pensja", title="Średnie wynagrodzenie w działach")
        st.plotly_chart(fig)
        st.caption(f"Działy poniżej {MIN_GRUPA} osób są ukryte (ochrona przed identyfikacją).")

        st.subheader(f"Tabela widoczna dla roli: {rola}")
        st.dataframe(widok_dla_roli(df, rola), hide_index=True)

# ======================================================================
# ZAGROŻENIE 1: CACHE
# ======================================================================
@st.cache_data(ttl=300)
def raport_zly(_rola: str):
    # BŁĄD: parametr z "_" na początku NIE wchodzi do klucza cache,
    # więc wynik pierwszej osoby dostaje każdy kolejny użytkownik.
    return widok_dla_roli(wczytaj(), _rola), datetime.now().strftime("%H:%M:%S")


@st.cache_data(ttl=300)
def raport_dobry(rola: str):
    # POPRAWNIE: rola jest częścią klucza cache -> osobny wpis dla każdej roli.
    return widok_dla_roli(wczytaj(), rola), datetime.now().strftime("%H:%M:%S")


with tab_cache:
    st.subheader("Zagrożenie 1: ujawnienie danych przez współdzielony cache")
    st.write(
        "Cache w Streamlit jest wspólny dla wszystkich sesji. Jeśli klucz cache "
        "nie uwzględnia użytkownika lub roli, kolejna osoba dostaje wynik zapisany "
        "dla poprzedniej."
    )
    if st.button("Wyczyść cache (reset demonstracji)"):
        st.cache_data.clear()
        st.success("Cache wyczyszczony.")

    kol_przed, kol_po = st.columns(2)
    with kol_przed:
        st.markdown("### PRZED (klucz cache bez roli)")
        st.caption("Kolejność: najpierw przycisk 1, potem 2.")
        if st.button("1. Admin otwiera raport", key="z1"):
            d, t = raport_zly("admin")
            st.caption(f"Wygenerowano: {t}")
            st.dataframe(d.head(5), hide_index=True)
        if st.button("2. Jan (zwykły user) otwiera raport", key="z2"):
            d, t = raport_zly("user")
            st.caption(f"Wygenerowano: {t} (ta sama godzina = wynik z cache admina)")
            st.error("Jan widzi pełne dane z PESEL-ami!" if "PESEL" in d.columns else "Brak wycieku")
            st.dataframe(d.head(5), hide_index=True)

    with kol_po:
        st.markdown("### PO (rola w kluczu cache)")
        st.caption("Zrób reset cache, potem te same kroki.")
        if st.button("1. Admin otwiera raport", key="d1"):
            d, t = raport_dobry("admin")
            st.caption(f"Wygenerowano: {t}")
            st.dataframe(d.head(5), hide_index=True)
        if st.button("2. Jan (zwykły user) otwiera raport", key="d2"):
            d, t = raport_dobry("user")
            st.caption(f"Wygenerowano: {t}")
            st.success("Jan widzi tylko zestawienie zagregowane.")
            st.dataframe(d.head(5), hide_index=True)

# ======================================================================
# ZAGROŻENIE 2: EKSPORT
# ======================================================================
with tab_eksport:
    st.subheader("Zagrożenie 2: eksport poufnych danych")
    kol_przed, kol_po = st.columns(2)
    with kol_przed:
        st.markdown("### PRZED")
        st.write("Każdy może pobrać pełny plik CSV, w tym PESEL i pensje, bez logowania i bez śladu w logach.")
        st.download_button(
            "Pobierz pełny CSV (niezabezpieczone)",
            df.to_csv(index=False).encode("utf-8-sig"),
            "raport_pelny.csv",
            "text/csv",
            key="exp_zly",
        )
    with kol_po:
        st.markdown("### PO")
        if not user:
            st.warning("Eksport wymaga logowania.")
        else:
            st.write(
                f"Rola **{rola}**: eksport obejmuje tylko dane dozwolone dla roli "
                "(PESEL zamaskowany lub tylko agregaty), z ochroną przed formula injection "
                "i zapisem w logu."
            )
            st.download_button(
                "Pobierz raport zgodny z uprawnieniami",
                bezpieczny_csv(widok_dla_roli(df, rola)),
                f"raport_{rola}.csv",
                "text/csv",
                key="exp_dobry",
                on_click=log,
                args=(user, "EKSPORT", f"rola={rola}"),
            )

# ======================================================================
# ZAGROŻENIE 3: UDOSTĘPNIANIE RAPORTÓW
# ======================================================================
RAPORTY_ID = {1: "agregat", 2: "lista płac", 3: "dane osobowe z PESEL"}

with tab_share:
    st.subheader("Zagrożenie 3: niekontrolowane udostępnianie raportów")
    kol_przed, kol_po = st.columns(2)

    with kol_przed:
        st.markdown("### PRZED")
        st.write("Raporty mają kolejne numery (1, 2, 3...) i otwierają się bez logowania. Atakujący może je zgadywać.")
        rid = st.number_input("ID raportu", 1, 10, 1, key="rid")
        if st.button("Otwórz raport (bez logowania)"):
            if rid == 1:
                st.dataframe(agregat(df), hide_index=True)
            elif rid == 2:
                st.dataframe(df[["Imie_Nazwisko", "Dzial", "Pensja"]].head(10), hide_index=True)
            elif rid == 3:
                st.error("Wyciek danych osobowych przez zgadnięcie ID!")
                st.dataframe(df.head(10), hide_index=True)
            else:
                st.info("Brak raportu.")

    with kol_po:
        st.markdown("### PO")
        st.write("Link zawiera losowy token, wygasa po 5 minutach, a otwarcie wymaga logowania. Zakres danych zależy od roli osoby otwierającej.")
        if user and st.button("Utwórz link (ważny 5 min)"):
            token = secrets.token_urlsafe(16)
            get_linki()[token] = {"wlasciciel": user, "wygasa": time.time() + 300}
            log(user, "UDOSTEPNIENIE", f"token={token[:6]}...")
            st.code(token)
        tok = st.text_input("Wklej token", key="tok")
        if st.button("Otwórz przez token"):
            wpis = get_linki().get(tok)
            if not user:
                log("anonim", "ODMOWA", "otwarcie linku bez logowania")
                st.error("Wymagane logowanie.")
            elif not wpis:
                log(user, "ODMOWA", "nieznany token")
                st.error("Nieprawidłowy token.")
            elif time.time() > wpis["wygasa"]:
                log(user, "ODMOWA", "token wygasł")
                st.error("Link wygasł.")
            else:
                log(user, "OTWARCIE_LINKU", f"od {wpis['wlasciciel']}")
                st.success("Dostęp przyznany. Dane przefiltrowane do Twojej roli.")
                st.dataframe(widok_dla_roli(df, rola).head(10), hide_index=True)

# ======================================================================
# ZAGROŻENIE 4: BRAK SZYFROWANIA
# ======================================================================
with tab_https:
    st.subheader("Zagrożenie 4: brak szyfrowania połączenia")
    st.markdown("**PRZED (HTTP):** `streamlit run app.py`, adres `http://localhost:8501`")
    st.markdown("**PO (HTTPS):** certyfikat samopodpisany (tylko do testów)")
    st.code(
        'openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem '
        '-days 30 -subj "/CN=localhost"\n'
        "streamlit run app.py --server.sslCertFile=cert.pem --server.sslKeyFile=key.pem",
        language="bash",
    )
    st.write("Adres po zmianie: `https://localhost:8501`")
    st.caption("W produkcji: certyfikat z zaufanego CA lub reverse proxy (np. nginx) z TLS.")

# ======================================================================
# LOGI I WYKRYWANIE INCYDENTÓW
# ======================================================================
with tab_log:
    st.subheader("Log zdarzeń i wykrywanie incydentów")
    if rola != "admin":
        st.warning("Dostęp tylko dla administratora.")
    else:
        zdarzenia = pd.DataFrame(get_log())
        if zdarzenia.empty:
            st.info("Brak zdarzeń.")
        else:
            alerty = zdarzenia[zdarzenia["zdarzenie"].isin(["ALERT", "ODMOWA", "BLOKADA"])]
            if len(alerty):
                st.error(f"Wykryto {len(alerty)} zdarzeń podejrzanych.")
            st.dataframe(zdarzenia.iloc[::-1], hide_index=True)
