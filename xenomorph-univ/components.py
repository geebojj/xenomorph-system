import streamlit as st
import bcrypt  # Added for crypto demo
from utils import log_audit, encrypt_sensitive, xor_encrypt_decrypt
from database import execute_sql_query
from data import has_permission

def school_profile():
    """Display Xenomorph University Profile."""
    st.markdown("""
# Xenomorph University: Forging the Future from the Unknown

**Where Innovation Meets the Infinite**  
Nestled at the crossroads of cutting-edge science and boundless imagination, Xenomorph University stands as a beacon for trailblazers who dare to explore the uncharted. Founded on the principle that true knowledge emerges from the shadows of the unknown, our institution transforms curiosity into cosmic achievement. Join us in reshaping tomorrow—one breakthrough at a time.

## Our Legacy: Born from Bold Vision
Established in 2042 amid the dawn of interstellar exploration, Xenomorph University was conceived by visionary scientists inspired by the resilient adaptability of life's most enigmatic forms. What began as a modest research outpost has evolved into a global powerhouse, blending rigorous academics with revolutionary research. Our motto, *Adapto et Explora* ("Adapt and Explore"), embodies the spirit of evolution and discovery that defines us. Today, we boast alumni leading NASA's Artemis missions, pioneering AI ethics at OpenAI, and innovating sustainable tech for a multi-planetary future.

## World-Class Academic Programs
At Xenomorph, education isn't just a degree—it's a launchpad to the stars. Our interdisciplinary curriculum fuses STEM, humanities, and speculative design to prepare you for realities yet to unfold.

- **Faculty of Xenobiology & Astrobiology**: Dive into the mysteries of extraterrestrial life, genetic engineering, and bio-adaptive technologies. Signature course: *Evolutionary Frontiers*—design your own synthetic organism.
- **Institute of Quantum Futures**: Master quantum computing, AI symbiosis, and predictive modeling. Collaborate on real-world projects like neural network simulations for climate resilience.
- **School of Speculative Arts & Design**: Where creativity meets code. Explore narrative architecture, holographic storytelling, and ethical VR worlds. Perfect for those who dream in dimensions.
- **Global Studies in Adaptive Societies**: Tackle geopolitics, cultural evolution, and resilient economies in an era of rapid change. Field studies include immersive simulations of off-world colonies.

With flexible majors, minors, and accelerated pathways, 95% of our graduates enter high-impact roles within six months—often with patents in hand.

## Vibrant Campus Life: Thrive in the Hive
Our 500-acre campus in the misty valleys of the Pacific Northwest pulses with energy, designed like a living ecosystem: adaptive spaces that evolve with student needs. Think solar-powered "morph pods" for study sessions, zero-gravity lounges for late-night debates, and bioluminescent gardens that glow under starlit skies.

- **Clubs & Societies**: From the Xenomorph Debate League.
- **Events**: Annual *Eclipse Expo*—a festival of hackathons, TED-style talks, and alien-themed galas. Plus, guest lectures from visionaries like Elon Musk and Yuval Noah Harari.
- **Wellness & Community**: Holistic support through adaptive counseling, mindfulness labs, and a diverse student body from 120+ countries. Inclusivity is our core code.

Diversity thrives here: 52% women in STEM, full scholarships for underrepresented innovators, and a zero-tolerance hive-mind for barriers.

## State-of-the-Art Facilities: Tools for Tomorrow
Equipped for the extraordinary, our labs rival those of MIT and CERN:

- **Morphogenics Research Center**: CRISPR suites and particle accelerators for hands-on genetic and physics experiments.
- **HoloArchive Library**: An AI-curated vault of 10 million+ volumes, with VR recreations of historical events.
- **Sustainability Nexus**: Net-zero energy campus with vertical farms and fusion prototypes—train to solve Earth's (and Mars') toughest challenges.

## Why Xenomorph? Your Edge in the Universe
In a world accelerating toward the unknown, Xenomorph University doesn't just prepare you—it evolves you. Our 98% employer satisfaction rate, $150K average starting salary, and network of 20,000+ alumni make us the ultimate accelerator. Whether you're decoding dark matter or designing dreamscapes, here, your potential has no limits.
    """)

def upload_visual_diagram(current_user, audit_log):
    """Admin function to upload and display diagram files (images/PDFs)."""
    st.subheader("Upload Diagram from Desktop")
    uploaded_file = st.file_uploader("Choose a file (PNG, JPG, JPEG, PDF)", type=['png', 'jpg', 'jpeg', 'pdf'])
    if uploaded_file is not None:
        file_details = {"FileName": uploaded_file.name, "FileType": uploaded_file.type, "FileSize": uploaded_file.size}
        st.write(file_details)
        if uploaded_file.type.startswith('image/'):
            st.image(uploaded_file, caption=f"Uploaded Diagram: {uploaded_file.name}", use_column_width=True)
        else:
            # For PDF, simple text preview
            st.write("PDF Content Preview (First 500 bytes):")
            st.text(uploaded_file.getvalue()[:500].decode('utf-8', errors='ignore'))
        if st.button("Log Upload"):
            audit_log = log_audit(audit_log, current_user, f"UPLOAD_VISUAL: {uploaded_file.name}")
            st.success("Upload logged!")
            return audit_log
    return audit_log

def sql_editor(current_user, audit_log):
    """Simple SQL Editor for Admin to query the database."""
    st.subheader("SQL Editor (Demo - Use SELECT only for safety)")
    st.warning("⚠️ For demo purposes only. Execute SELECT queries to view data. Avoid DML/DDL in production.")
    query = st.text_area("Enter SQL Query", height=100, value="SELECT * FROM users;")
    if st.button("Execute Query"):
        if query.strip().upper().startswith('SELECT'):
            result_df = execute_sql_query(query)
            st.dataframe(result_df)
            if not result_df.empty and 'Error' not in result_df.columns:
                csv = result_df.to_csv(index=False)
                st.download_button("Download Results", csv, "query_results.csv", "text/csv")
                audit_log = log_audit(audit_log, current_user, f"SQL_QUERY: {query[:50]}...")
                return audit_log
        else:
            st.error("Only SELECT queries allowed for safety.")
    return audit_log

def crypto_demo():
    """Crypto Demo: Hashing (bcrypt) and XOR (Simple Cipher)."""
    st.info("**Hashing:** One-way (e.g., passwords). Irreversible; used for verification. **XOR:** Reversible symmetric cipher (demo only; weak for prod—use AES). Trade-off: Simplicity vs. Security.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Hashing Demo (bcrypt)")
        demo_data = st.text_input("Input for Hash (e.g., SSN)", value="123-45-6789")
        hashed = None
        if st.button("Hash It"):
            hashed = bcrypt.hashpw(demo_data.encode(), bcrypt.gensalt()).decode()
            st.code(hashed)
            st.write("**Verify:** Enter original to check match.")
        verify_input = st.text_input("Verify Input")
        if st.button("Check Match") and hashed:
            if bcrypt.checkpw(verify_input.encode(), hashed.encode()):
                st.success("Match! (Secure storage demo)")
            else:
                st.error("No Match.")
    
    with col2:
        st.subheader("XOR Demo (Encrypt/Decrypt)")
        xor_key = st.text_input("Key (e.g., secretkey)", value="key")
        xor_data = st.text_input("Data to XOR", value="sensitive_data")
        encrypted = None
        if st.button("Encrypt/Decrypt"):
            encrypted = xor_encrypt_decrypt(xor_data, xor_key)
            st.code(f"Encrypted: {encrypted}")
            st.write("**Decrypt:** Reuse same key on encrypted output.")
        if st.button("Decrypt (from Encrypted)") and encrypted:
            decrypted = xor_encrypt_decrypt(encrypted, xor_key)
            if decrypted == xor_data:
                st.success(f"Decrypted: {decrypted} (Matches original!)")
            else:
                st.error("Decrypt failed (key mismatch).")