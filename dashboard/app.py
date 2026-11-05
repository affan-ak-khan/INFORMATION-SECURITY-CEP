import glob, os
import pandas as pd
import altair as alt
import streamlit as st

st.set_page_config(page_title="Ransomware Guard", layout="wide")
LOGS = os.path.join(os.path.dirname(__file__), "..", "logs")
COLORS = {"normal": "#1f7a4d", "SUSPICIOUS": "#b8860b", "LIKELY": "#d2691e", "CONFIRMED": "#b3261e"}
MESSAGES = {
    "normal": "All quiet - no ransomware-like activity",
    "SUSPICIOUS": "Suspicious activity - container throttled",
    "LIKELY": "Likely attack - container isolated from network",
    "CONFIRMED": "Attack confirmed - snapshot saved, container killed",
}
STAGES = [
    ("SUSPICIOUS", "1. Throttle", "Limit container CPU"),
    ("LIKELY", "2. Isolate", "Cut network access"),
    ("CONFIRMED", "3. Snapshot + Kill", "Forensic copy, then stop"),
]
ACTION_NAMES = {s[0]: s[1] for s in STAGES}

st.markdown("""<style>
.block-container {padding-top: 2rem; max-width: 1400px;}
.banner {border-radius: 14px; padding: 22px 28px; color: white; margin-bottom: 18px;}
.banner .lvl {font-size: 2.2rem; font-weight: 700;}
.banner .msg {font-size: 1.15rem; opacity: .92;}
.card {background: #1b2230; border: 1px solid #2c3648; border-radius: 12px; padding: 16px 20px;}
.card .lab {font-size: .95rem; color: #9aa7bd;}
.card .val {font-size: 2rem; font-weight: 700; color: #f2f5fa;}
.stage {border-radius: 12px; padding: 16px 20px; border: 1px solid #2c3648; background: #151b27; color: #6f7c93;}
.stage.on {background: #3a1d1d; border-color: #b3261e; color: #ffd9d6;}
.stage .t {font-size: 1.2rem; font-weight: 700;}
</style>""", unsafe_allow_html=True)


def latest_dir():
    cands = []
    for p in [LOGS] + glob.glob(os.path.join(LOGS, "eval", "*")):
        f = os.path.join(p, "events.csv")
        if os.path.exists(f):
            cands.append((os.path.getmtime(f), p))
    return max(cands)[1] if cands else LOGS


def load(name, cols, folder):
    try:
        return pd.read_csv(os.path.join(folder, name), names=cols)
    except Exception:
        return pd.DataFrame(columns=cols)


def chart(df, col, top, rules, color):
    d = df[[col]].astype(float).reset_index().rename(columns={"index": "n"})
    d["n"] = d["n"] + 1
    line = alt.Chart(d).mark_line(point=True, color=color, strokeWidth=3).encode(
        x=alt.X("n:Q", title="file event #", axis=alt.Axis(tickMinStep=1, format="d")),
        y=alt.Y(col + ":Q", title=col, scale=alt.Scale(domain=[0, top])))
    r = alt.Chart(pd.DataFrame({"y": rules})).mark_rule(
        strokeDash=[5, 5], color="#ff6b6b").encode(y="y:Q")
    return (line + r).properties(height=300).configure_axis(
        labelFontSize=13, titleFontSize=14, labelColor="#c9d3e6",
        titleColor="#c9d3e6", gridColor="#2c3648").configure_view(strokeWidth=0)


def card(col, label, value):
    col.markdown('<div class="card"><div class="lab">%s</div><div class="val">%s</div></div>'
                 % (label, value), unsafe_allow_html=True)


st.title("Ransomware Guard")
st.caption("Multi-signal ransomware detection in containerized environments - SE 401")


@st.fragment(run_every=1)
def live():
    folder = latest_dir()
    ev = load("events.csv", ["t", "file", "entropy", "E", "IO", "X", "score", "level"], folder)
    ac = load("actions.csv", ["t", "target", "level"], folder)
    level = ev["level"].iloc[-1] if len(ev) else "normal"
    reached = set(ac["level"]) if len(ac) else set()

    rel = os.path.relpath(folder, LOGS)
    if rel == ".":
        st.caption("Source: live demo logs")
    else:
        st.caption("Source: evaluation trial " + rel + " (observe-only, no real action)")

    st.markdown('<div class="banner" style="background:%s"><div class="lvl">%s</div><div class="msg">%s</div></div>'
                % (COLORS.get(level, "#1f7a4d"), level, MESSAGES.get(level, "")), unsafe_allow_html=True)

    c = st.columns(4)
    card(c[0], "Files seen", len(ev))
    card(c[1], "Max entropy", ("%.2f" % ev["entropy"].astype(float).max()) if len(ev) else "-")
    card(c[2], "Max risk score", ("%.2f" % ev["score"].astype(float).max()) if len(ev) else "-")
    card(c[3], "Alerts raised", len(ac))

    st.markdown("### Automated response")
    s = st.columns(3)
    for col, (lvl, title, sub) in zip(s, STAGES):
        on = " on" if lvl in reached else ""
        status = "TRIGGERED" if lvl in reached else "standby"
        col.markdown('<div class="stage%s"><div class="t">%s</div><div>%s</div><div>%s</div></div>'
                     % (on, title, sub, status), unsafe_allow_html=True)

    if len(ev):
        a, b = st.columns(2)
        a.markdown("### File entropy (bits/byte)")
        a.altair_chart(chart(ev, "entropy", 8.5, [7.5], "#4da3ff"), use_container_width=True)
        b.markdown("### Composite risk score")
        b.altair_chart(chart(ev, "score", 1.05, [0.5, 0.7, 0.9], "#ffb454"), use_container_width=True)
        st.markdown("### Latest file events")
        last = ev.tail(10).iloc[::-1][["file", "entropy", "E", "IO", "X", "score", "level"]]
        st.dataframe(last, use_container_width=True, hide_index=True)
    else:
        st.info("Waiting for file activity...")

    st.markdown("### Alert log")
    if len(ac):
        ac["time"] = pd.to_datetime(ac["t"], unit="s")
        ac["action"] = ac["level"].map(ACTION_NAMES)
        st.dataframe(ac[["time", "target", "level", "action"]], use_container_width=True, hide_index=True)
    else:
        st.write("No alerts yet.")


live()
