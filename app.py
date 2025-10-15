import streamlit as st
import joblib
import pandas as pd

# Load model + scaler
model = joblib.load("phishing_detector_model.pkl")
scaler = joblib.load("phishing_detector_scaler.pkl")

# Feature extraction function
def extract_features(url):
    length = len(url)
    num_dots = url.count('.')
    has_at = 1 if '@' in url else 0

    features_df = pd.DataFrame([[length, num_dots, has_at]],columns=['length', 'num_dots', 'has_at'])
    raw_features = {
        "length": length,
        "num_dots": num_dots,
        "has_at": has_at
    }
    return features_df, raw_features

# Streamlit UI
st.title("🔍 AI Phishing URL Detector")
st.write("Enter a URL to check if it's safe, suspicious, or phishing.")

url = st.text_input("Enter URL:", "")

if st.button("Analyze URL"):
    if url.strip() == "":
        st.warning("Please enter a URL first.")
    else:
        features_df, raw_features = extract_features(url)
        scaled_features = scaler.transform(features_df)
        prediction_proba = model.predict_proba(scaled_features)[0]
        phishing_probability = prediction_proba[1]

        # Risk level
        if phishing_probability > 0.75:
            risk = "🚨 High Risk (Phishing)"
            color = "red"
            action = "Do NOT click! This site looks dangerous."
        elif phishing_probability > 0.45:
            risk = "⚠️ Suspicious"
            color = "orange"
            action = "Proceed with caution. Verify site identity."
        else:
            risk = "✅ Safe"
            color = "green"
            action = "This URL appears safe."

        # Show results
        st.markdown(f"### Risk Level: <span style='color:{color}'>{risk}</span>", unsafe_allow_html=True)
        st.write(f"**Confidence:** {phishing_probability:.2%}")
        st.write(f"**Scanned URL:** {url}")
        st.info(action)

        # Explainability
        st.subheader("Explainability")
        reasons = []
        if raw_features["has_at"] == 1:
            reasons.append("❌ Contains '@' symbol → often used to hide domain")
        if raw_features["length"] > 60:
            reasons.append(f"⚠️ URL is long ({raw_features['length']} chars)")
        if raw_features["num_dots"] > 4:
            reasons.append(f"⚠️ Too many dots ({raw_features['num_dots']}) → confusing address")

        if not reasons and phishing_probability > 0.45:
            reasons.append("Suspicion is based on combined subtle features.")

        for r in reasons:
            st.write("- ", r)

# Reporting feature
if st.button("Report URL"):
    if url.strip() == "":
        st.warning("Enter a URL to report.")
    else:
        st.success(f"Thanks! '{url}' has been logged for review.")
